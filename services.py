from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Any
from uuid import uuid4

DATE_FORMATS = ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d")


def parse_master_date(value: Any) -> date | None:
    """Parse supported master-data dates without changing the source value."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if not isinstance(value, str):
        return None
    raw = value.strip()
    for date_format in DATE_FORMATS:
        try:
            return datetime.strptime(raw, date_format).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def as_utc_datetime(value: date | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return datetime.combine(value, time.min, tzinfo=timezone.utc)


def as_date(value: date | datetime | None) -> date | None:
    return value.date() if isinstance(value, datetime) else value


def calculate_kyc_status(
    kyc: dict[str, Any], latest_rekyc: dict[str, Any] | None, warning_days: int
) -> str:
    if latest_rekyc and latest_rekyc.get("status") == "SCHEDULED":
        return "RE_KYC_SCHEDULED"
    if latest_rekyc and latest_rekyc.get("status") == "COMPLETED":
        return "RE_KYC_COMPLETED"
    expiry = as_date(kyc.get("expiry_date"))
    if expiry is None or as_date(kyc.get("kyc_date")) is None:
        return "MISSING_DATA"
    today = date.today()
    if expiry < today:
        return "EXPIRED"
    if expiry <= today + timedelta(days=warning_days):
        return "EXPIRING_SOON"
    return "VALID"


def refresh_kyc_statuses(db, warning_days: int) -> None:
    for kyc in db.kyc_records.find({}):
        latest = db.rekyc_records.find_one({"kyc_id": kyc["kyc_id"]}, sort=[("created_at", -1)])
        status = calculate_kyc_status(kyc, latest, warning_days)
        if kyc.get("status") != status:
            db.kyc_records.update_one({"kyc_id": kyc["kyc_id"]}, {"$set": {"status": status}})


def refresh_data_quality_issues(db) -> list[dict[str, Any]]:
    """Persist current DOB/document date issues while retaining their raw values."""
    now = datetime.now(timezone.utc)
    active_ids: list[str] = []
    for customer in db.customers.find({}, {"customer_id": 1, "name": 1, "dob_raw": 1, "dob_status": 1}):
        if customer.get("dob_status") != "VALID":
            issue_id = f"customer:{customer['customer_id']}:dob"
            active_ids.append(issue_id)
            raw = customer.get("dob_raw") or ""
            db.data_quality_issues.update_one(
                {"issue_id": issue_id},
                {"$set": {
                    "entity_type": "customer", "entity_id": customer["customer_id"],
                    "customer_id": customer["customer_id"], "customer_name": customer.get("name", ""), "field": "date_of_birth",
                    "issue_type": "MISSING" if not raw else "INVALID",
                    "source_value": raw, "message": "Date of birth is missing." if not raw else "Date of birth could not be parsed; the source value was preserved.",
                    "updated_at": now,
                }, "$setOnInsert": {"created_at": now}},
                upsert=True,
            )
    for kyc in db.kyc_records.find({}, {"kyc_id": 1, "customer_id": 1, "expiry_date_raw": 1, "expiry_date": 1, "kyc_date_raw": 1, "kyc_date": 1}):
        customer = db.customers.find_one({"customer_id": kyc["customer_id"]}, {"name": 1}) or {}
        for field, raw_field, normalized_field, label in (
            ("expiry_date", "expiry_date_raw", "expiry_date", "document expiry date"),
            ("kyc_date", "kyc_date_raw", "kyc_date", "KYC date"),
        ):
            if kyc.get(normalized_field) is not None:
                continue
            raw = kyc.get(raw_field) or ""
            issue_id = f"kyc:{kyc['kyc_id']}:{field}"
            active_ids.append(issue_id)
            db.data_quality_issues.update_one(
                {"issue_id": issue_id},
                {"$set": {
                    "entity_type": "kyc_record", "entity_id": kyc["kyc_id"],
                    "customer_id": kyc["customer_id"], "customer_name": customer.get("name", ""),
                    "field": field, "issue_type": "MISSING" if not raw else "INVALID",
                    "source_value": raw, "message": f"{label.capitalize()} is missing." if not raw else f"{label.capitalize()} could not be parsed; the source value was preserved.",
                    "updated_at": now,
                }, "$setOnInsert": {"created_at": now}},
                upsert=True,
            )
    if active_ids:
        db.data_quality_issues.delete_many({"issue_id": {"$nin": active_ids}})
    else:
        db.data_quality_issues.delete_many({})
    return list(db.data_quality_issues.find({}).sort("updated_at", -1))


def scan_expiring_kyc(db, warning_days: int, today: date | None = None) -> int:
    today = today or date.today()
    cutoff = as_utc_datetime(today + timedelta(days=warning_days))
    today_dt = as_utc_datetime(today)
    created = 0
    for kyc in db.kyc_records.find({"expiry_date": {"$ne": None, "$lte": cutoff}}):
        expiry = as_date(kyc.get("expiry_date"))
        if expiry is None:
            continue
        existing = db.rekyc_records.find_one({"active_task_key": kyc["kyc_id"]})
        completed_for_same_expiry = db.rekyc_records.find_one({
            "kyc_id": kyc["kyc_id"], "status": "COMPLETED", "expiry_snapshot": kyc["expiry_date"]
        })
        if existing or completed_for_same_expiry:
            continue
        customer = db.customers.find_one({"customer_id": kyc["customer_id"]}) or {}
        account = kyc.get("account_number") or (customer.get("account_numbers") or [""])[0]
        db.rekyc_records.insert_one({
            "rekyc_id": f"RK-{kyc['kyc_id']}-{uuid4().hex[:10]}",
            "kyc_id": kyc["kyc_id"], "customer_id": kyc["customer_id"],
            "customer_name": customer.get("name", ""), "account_number": account,
            "branch_id": customer.get("branch_id", ""), "branch_name": customer.get("branch_name", ""),
            "document_type": kyc.get("document_type", ""), "expiry_snapshot": kyc["expiry_date"],
            "scheduled_date": None, "completed_date": None, "status": "PENDING",
            "assigned_officer": "", "remarks": "", "active_task_key": kyc["kyc_id"],
            "created_at": today_dt, "updated_at": today_dt,
        })
        created += 1
    return created
def json_safe(value: Any) -> Any:
    """Convert BSON/date values recursively into JSON-compatible values."""
    if isinstance(value, dict):
        from bson import ObjectId
        return {("id" if key == "_id" else key): json_safe(item) for key, item in value.items() if key != "_id" or not isinstance(item, ObjectId)}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value
