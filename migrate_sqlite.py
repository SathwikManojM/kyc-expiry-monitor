"""One-time import of the original Flask/SQLite records into MongoDB."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from database import get_database, initialize_database
from services import as_utc_datetime, parse_master_date, refresh_data_quality_issues, refresh_kyc_statuses


def parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def migrate(source: Path) -> tuple[int, int, int]:
    if not source.exists():
        raise FileNotFoundError(f"SQLite source database does not exist: {source}")
    db = get_database()
    db.command("ping")
    initialize_database(db, seed_demo=False)
    sqlite_db = sqlite3.connect(source)
    sqlite_db.row_factory = sqlite3.Row
    customers_added = kyc_added = tasks_added = 0
    try:
        holders = sqlite_db.execute("SELECT * FROM account_holders ORDER BY id").fetchall()
        for holder in holders:
            customer_id = holder["customer_id"]
            dob_raw = holder["dob_text"] or ""
            dob = parse_master_date(dob_raw)
            customer = {
                "customer_id": customer_id,
                "name": holder["full_name"],
                "date_of_birth": as_utc_datetime(dob),
                "dob_raw": dob_raw,
                "dob_status": "VALID" if dob else ("MISSING" if not dob_raw else "INVALID"),
                "branch_id": holder["branch"].upper().replace(" ", "-"),
                "branch_name": holder["branch"],
                "account_numbers": [holder["account_number"]],
                "customer_type": "INDIVIDUAL",
                "phone": holder["phone"] or "",
                "created_at": parse_timestamp(holder["created_at"]),
                "updated_at": datetime.now(timezone.utc),
            }
            result = db.customers.update_one({"customer_id": customer_id}, {"$setOnInsert": customer}, upsert=True)
            customers_added += int(result.upserted_id is not None)
            branch_id = customer["branch_id"]
            db.branches.update_one(
                {"branch_id": branch_id},
                {"$setOnInsert": {"branch_id": branch_id, "branch_name": holder["branch"], "location": "", "manager_name": "", "status": "ACTIVE"}},
                upsert=True,
            )
            account_number = holder["account_number"]
            db.accounts.update_one(
                {"account_number": account_number},
                {"$setOnInsert": {"account_number": account_number, "branch_id": branch_id, "account_type": "SAVINGS", "joint_account": False, "status": "ACTIVE"}, "$addToSet": {"holder_ids": customer_id}},
                upsert=True,
            )
            docs = sqlite_db.execute("SELECT * FROM kyc_documents WHERE holder_id = ?", (holder["id"],)).fetchall()
            for document in docs:
                expiry_raw = document["expiry_date"] or ""
                kyc_id = f"KYC-LEGACY-{document['id']}"
                expiry = parse_master_date(expiry_raw)
                record = {
                    "kyc_id": kyc_id, "customer_id": customer_id, "account_number": account_number,
                    "document_type": document["document_type"], "document_number": document["document_number"],
                    "issue_date": None, "expiry_date": as_utc_datetime(expiry), "expiry_date_raw": expiry_raw,
                    # SQLite did not store KYC dates; preserve them as missing, not as the DOB.
                    "kyc_date": None, "kyc_date_raw": "",
                    "verified_at": parse_timestamp(document["verified_at"]) if document["verified_at"] else None,
                    "status": "ACTIVE", "last_updated": datetime.now(timezone.utc),
                }
                result = db.kyc_records.update_one({"kyc_id": kyc_id}, {"$setOnInsert": record}, upsert=True)
                kyc_added += int(result.upserted_id is not None)
                old_task = sqlite_db.execute("SELECT * FROM rekyc_tasks WHERE document_id = ?", (document["id"],)).fetchone()
                if old_task:
                    task_status = {"Pending": "PENDING", "Scheduled": "SCHEDULED", "Completed": "COMPLETED"}.get(old_task["status"], "PENDING")
                    task = {
                        "rekyc_id": f"RK-LEGACY-{old_task['id']}", "kyc_id": kyc_id,
                        "customer_id": customer_id, "customer_name": holder["full_name"],
                        "account_number": account_number, "branch_id": branch_id, "branch_name": holder["branch"],
                        "document_type": document["document_type"], "expiry_snapshot": as_utc_datetime(expiry),
                        "scheduled_date": as_utc_datetime(parse_master_date(old_task["scheduled_for"])) if old_task["scheduled_for"] else None,
                        "completed_date": parse_timestamp(old_task["created_at"]) if task_status == "COMPLETED" else None,
                        "status": task_status, "assigned_officer": "", "remarks": "Imported from SQLite",
                        "created_at": parse_timestamp(old_task["created_at"]), "updated_at": datetime.now(timezone.utc),
                    }
                    if task_status != "COMPLETED":
                        task["active_task_key"] = kyc_id
                    result = db.rekyc_records.update_one({"rekyc_id": task["rekyc_id"]}, {"$setOnInsert": task}, upsert=True)
                    tasks_added += int(result.upserted_id is not None)
        # Accounts sharing more than one holder are explicitly marked joint.
        for account in db.accounts.find({}):
            if len(account.get("holder_ids", [])) > 1:
                db.accounts.update_one({"account_number": account["account_number"]}, {"$set": {"joint_account": True, "account_type": "JOINT"}})
                db.customers.update_many({"account_numbers": account["account_number"]}, {"$set": {"customer_type": "JOINT"}})
        refresh_data_quality_issues(db)
        refresh_kyc_statuses(db, 60)
    finally:
        sqlite_db.close()
    return customers_added, kyc_added, tasks_added


if __name__ == "__main__":
    default_source = Path(__file__).resolve().parent / "instance" / "kyc_monitor.db"
    source_path = Path(os.environ.get("KYC_LEGACY_SQLITE", default_source))
    imported = migrate(source_path)
    print(f"MongoDB import complete: {imported[0]} customers, {imported[1]} KYC records, {imported[2]} re-KYC tasks.")
