from __future__ import annotations

import asyncio
import csv
import io
import os
import secrets
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError
from starlette.middleware.sessions import SessionMiddleware

from database import get_database, initialize_database
from id_photo_scan import ALLOWED_IMAGE_TYPES, MAX_IMAGE_BYTES, PhotoScanError, scan_id_photo
from models import CustomerCreate, CustomerPage, RekycCompleteRequest, RekycScheduleRequest, TokenResponse
from security import SECRET_KEY, create_access_token, decode_access_token, verify_password
from services import (
    as_date,
    as_utc_datetime,
    calculate_kyc_status,
    json_safe,
    parse_master_date,
    refresh_data_quality_issues,
    refresh_kyc_statuses,
    scan_expiring_kyc,
)

BASE_DIR = Path(__file__).resolve().parent
WARNING_DAY_OPTIONS = (30, 60, 90)
try:
    DEFAULT_WARNING_DAYS = int(os.environ.get("KYC_EXPIRY_WARNING_DAYS", "60"))
except ValueError:
    DEFAULT_WARNING_DAYS = 60
if DEFAULT_WARNING_DAYS not in WARNING_DAY_OPTIONS:
    DEFAULT_WARNING_DAYS = 60


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db = get_database()
    db.command("ping")
    initialize_database(db)
    refresh_data_quality_issues(db)
    scan_expiring_kyc(db, DEFAULT_WARNING_DAYS)
    refresh_kyc_statuses(db, DEFAULT_WARNING_DAYS)
    yield


app = FastAPI(
    title="KYC Watch API",
    description="Admin-only KYC expiry monitoring and branch compliance APIs.",
    version="2.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="kyc_admin_session",
    same_site="lax",
    https_only=os.environ.get("KYC_COOKIE_SECURE", "false").lower() == "true",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def get_db() -> Database:
    return get_database()


def get_api_admin(
    token: Annotated[str, Depends(oauth2_scheme)], db: Annotated[Database, Depends(get_db)]
) -> dict[str, Any]:
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired administrator token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    admin = db.admin_users.find_one({"username": payload["sub"], "role": "admin"})
    if admin is None:
        raise HTTPException(status_code=401, detail="Administrator account is unavailable.")
    return admin


def current_session_admin(request: Request, db: Database) -> dict[str, Any] | None:
    username = request.session.get("admin_username")
    if not username:
        return None
    admin = db.admin_users.find_one({"username": username, "role": "admin"})
    if admin is None:
        request.session.clear()
        return None
    return {"name": admin["username"], "username": admin["username"], "role": "admin"}


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, submitted: str) -> None:
    expected = request.session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(expected, submitted or ""):
        raise HTTPException(status_code=400, detail="Invalid CSRF token. Refresh the page and try again.")


def add_flash(request: Request, message: str, category: str = "success") -> None:
    flashes = request.session.get("_flashes", [])
    flashes.append((category, message))
    request.session["_flashes"] = flashes


def render_page(
    request: Request,
    template_name: str,
    db: Database,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
) -> Response:
    admin = current_session_admin(request, db)

    def get_flashed_messages(with_categories: bool = False):
        messages = request.session.pop("_flashes", [])
        return messages if with_categories else [message for _, message in messages]

    page_context = {
        "request": request,
        "current_user": admin,
        "csrf_token": lambda: csrf_token(request),
        "get_flashed_messages": get_flashed_messages,
    }
    page_context.update(context or {})
    return templates.TemplateResponse(
        request=request, name=template_name, context=page_context, status_code=status_code
    )


def safe_warning_days(raw: str | int | None) -> int:
    try:
        value = int(raw or DEFAULT_WARNING_DAYS)
    except (TypeError, ValueError):
        return DEFAULT_WARNING_DAYS
    return value if value in WARNING_DAY_OPTIONS else DEFAULT_WARNING_DAYS


def date_for_filter(raw: str | None) -> date | None:
    return parse_master_date(raw) if raw else None


def mask_document_number(value: str) -> str:
    if len(value) <= 4:
        return "•" * len(value)
    return f"{value[:2]}{'•' * (len(value) - 4)}{value[-2:]}"


def make_customer_record(payload: CustomerCreate, db: Database) -> tuple[dict[str, Any], dict[str, Any]]:
    now = datetime.now(timezone.utc)
    dob = parse_master_date(payload.date_of_birth)
    expiry = parse_master_date(payload.expiry_date)
    issue = parse_master_date(payload.issue_date)
    kyc_date = parse_master_date(payload.kyc_date)
    existing_account = db.accounts.find_one({"account_number": payload.account_number.strip()})
    is_joint = payload.customer_type == "JOINT" or bool(existing_account and existing_account.get("holder_ids"))
    customer = {
        "customer_id": payload.customer_id.strip(),
        "name": payload.name.strip(),
        "date_of_birth": as_utc_datetime(dob),
        "dob_raw": payload.date_of_birth.strip(),
        "dob_status": "VALID" if dob else ("MISSING" if not payload.date_of_birth.strip() else "INVALID"),
        "branch_id": payload.branch_id.strip(),
        "branch_name": payload.branch_name.strip(),
        "account_numbers": [payload.account_number.strip()],
        "customer_type": "JOINT" if is_joint else "INDIVIDUAL",
        "created_at": now,
        "updated_at": now,
    }
    kyc_id = f"KYC-{payload.customer_id.strip()}-{secrets.token_hex(4)}"
    kyc = {
        "kyc_id": kyc_id,
        "customer_id": customer["customer_id"],
        "account_number": payload.account_number.strip(),
        "document_type": payload.document_type.strip(),
        "document_number": payload.document_number.strip(),
        "issue_date": as_utc_datetime(issue),
        "issue_date_raw": payload.issue_date.strip(),
        "expiry_date": as_utc_datetime(expiry),
        "expiry_date_raw": payload.expiry_date.strip(),
        "kyc_date": as_utc_datetime(kyc_date),
        "kyc_date_raw": payload.kyc_date.strip(),
        "status": "ACTIVE",
        "last_updated": now,
    }
    branch = db.branches.find_one({"branch_id": customer["branch_id"]})
    if branch is None:
        db.branches.insert_one({
            "branch_id": customer["branch_id"], "branch_name": customer["branch_name"],
            "location": "", "manager_name": "", "status": "ACTIVE", "created_at": now,
        })
    db.customers.insert_one(customer)
    db.kyc_records.insert_one(kyc)
    db.accounts.update_one(
        {"account_number": kyc["account_number"]},
        {
            "$setOnInsert": {
                "account_number": kyc["account_number"], "branch_id": customer["branch_id"],
                "account_type": "JOINT" if is_joint else "SAVINGS",
                "joint_account": is_joint, "status": "ACTIVE", "created_at": now,
            },
            "$addToSet": {"holder_ids": customer["customer_id"]},
        },
        upsert=True,
    )
    if is_joint:
        db.accounts.update_one({"account_number": kyc["account_number"]}, {"$set": {"joint_account": True, "account_type": "JOINT"}})
        db.customers.update_many({"account_numbers": kyc["account_number"]}, {"$set": {"customer_type": "JOINT"}})
    refresh_data_quality_issues(db)
    refresh_kyc_statuses(db, DEFAULT_WARNING_DAYS)
    return customer, kyc


def kyc_view_rows(
    db: Database,
    warning_days: int,
    *,
    branch_id: str = "",
    kyc_status: str = "",
    document_type: str = "",
    rekyc_status: str = "",
    expiry_from: date | None = None,
    expiry_to: date | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for kyc in db.kyc_records.find({}).sort("expiry_date", 1):
        customer = db.customers.find_one({"customer_id": kyc["customer_id"]}) or {}
        latest = db.rekyc_records.find_one({"kyc_id": kyc["kyc_id"]}, sort=[("created_at", -1)])
        computed_status = calculate_kyc_status(kyc, latest, warning_days)
        expiry = as_date(kyc.get("expiry_date"))
        scheduled = as_date(latest.get("scheduled_date")) if latest else None
        row = {
            "kyc_id": kyc["kyc_id"], "customer_id": kyc["customer_id"],
            "full_name": customer.get("name", "Unknown"), "name": customer.get("name", "Unknown"),
            "account_number": kyc.get("account_number", ""),
            "branch_id": customer.get("branch_id", ""), "branch": customer.get("branch_name", "Unknown"),
            "dob_text": customer.get("dob_raw", ""), "dob_status": customer.get("dob_status", "MISSING"),
            "document_type": kyc.get("document_type", ""), "document_number": mask_document_number(kyc.get("document_number", "")),
            "expiry_date": expiry.isoformat() if expiry else "", "expiry_date_raw": kyc.get("expiry_date_raw", ""),
            "kyc_date": as_date(kyc.get("kyc_date")).isoformat() if kyc.get("kyc_date") else "",
            "kyc_status": computed_status, "status": computed_status,
            "rekyc_id": latest.get("rekyc_id", "") if latest else "",
            "rekyc_status": latest.get("status", "") if latest else "",
            "scheduled_for": scheduled.isoformat() if scheduled else "",
            "assigned_officer": latest.get("assigned_officer", "") if latest else "",
            "days_left": (expiry - date.today()).days if expiry else None,
            "customer_type": customer.get("customer_type", "INDIVIDUAL"),
        }
        if branch_id and row["branch_id"] != branch_id:
            continue
        if kyc_status and computed_status != kyc_status:
            continue
        if document_type and row["document_type"] != document_type:
            continue
        if rekyc_status and row["rekyc_status"] != rekyc_status:
            continue
        if expiry_from and (expiry is None or expiry < expiry_from):
            continue
        if expiry_to and (expiry is None or expiry > expiry_to):
            continue
        compare_date = scheduled or expiry
        if date_from and (compare_date is None or compare_date < date_from):
            continue
        if date_to and (compare_date is None or compare_date > date_to):
            continue
        rows.append(row)
    return rows


def dashboard_statistics(db: Database, warning_days: int) -> tuple[dict[str, int], list[dict[str, Any]]]:
    rows = kyc_view_rows(db, warning_days)
    stats = {
        "total_customers": db.customers.count_documents({}),
        "total_accounts": db.accounts.count_documents({}),
        "expired_kyc": sum(row["kyc_status"] == "EXPIRED" for row in rows),
        "expiring_soon": sum(row["kyc_status"] == "EXPIRING_SOON" for row in rows),
        "pending_rekyc": db.rekyc_records.count_documents({"status": "PENDING"}),
        "scheduled_rekyc": db.rekyc_records.count_documents({"status": "SCHEDULED"}),
        "completed_rekyc": db.rekyc_records.count_documents({"status": "COMPLETED"}),
        "data_quality_issues": db.data_quality_issues.count_documents({}),
    }
    return stats, rows


def matching_report_rows(
    db: Database, warning_days: int, *, branch_id: str = "", kyc_status: str = "",
    document_type: str = "", rekyc_status: str = "", expiry_from: str = "",
    expiry_to: str = "", date_from: str = "", date_to: str = "",
) -> list[dict[str, Any]]:
    return kyc_view_rows(
        db, warning_days, branch_id=branch_id, kyc_status=kyc_status,
        document_type=document_type, rekyc_status=rekyc_status,
        expiry_from=date_for_filter(expiry_from), expiry_to=date_for_filter(expiry_to),
        date_from=date_for_filter(date_from), date_to=date_for_filter(date_to),
    )


def paginate(items: list[dict[str, Any]], page: int, page_size: int) -> dict[str, Any]:
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "page": page, "page_size": page_size, "total": len(items)}


def session_required(request: Request, db: Database) -> dict[str, Any] | None:
    return current_session_admin(request, db)


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok", "database": "MongoDB"}


@app.get("/login", response_class=HTMLResponse, name="login")
def login_page(request: Request, db: Annotated[Database, Depends(get_db)]):
    if session_required(request, db):
        return RedirectResponse("/", status_code=303)
    return render_page(request, "login.html", db)


@app.post("/login", response_class=HTMLResponse, name="login_submit")
def login_submit(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    submitted_csrf: Annotated[str, Form(alias="csrf_token")],
    db: Annotated[Database, Depends(get_db)],
):
    verify_csrf(request, submitted_csrf)
    admin = db.admin_users.find_one({"username": username.strip().lower(), "role": "admin"})
    if admin is None or not verify_password(password, admin.get("password_hash", "")):
        add_flash(request, "Administrator username or password is incorrect.", "error")
        return render_page(request, "login.html", db, status_code=401)
    request.session.clear()
    request.session["admin_username"] = admin["username"]
    csrf_token(request)
    return RedirectResponse("/", status_code=303)


@app.post("/logout", name="logout")
def logout(
    request: Request,
    submitted_csrf: Annotated[str, Form(alias="csrf_token")],
):
    verify_csrf(request, submitted_csrf)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse, name="dashboard")
def dashboard(
    request: Request,
    db: Annotated[Database, Depends(get_db)],
    warning_days: str = str(DEFAULT_WARNING_DAYS),
    branch: str = "",
    q: str = "",
):
    admin = session_required(request, db)
    if admin is None:
        return RedirectResponse("/login", status_code=303)
    warning = safe_warning_days(warning_days)
    scan_expiring_kyc(db, warning)
    refresh_data_quality_issues(db)
    refresh_kyc_statuses(db, warning)
    stats, all_rows = dashboard_statistics(db, warning)
    tasks = [row for row in all_rows if row["rekyc_status"] in {"PENDING", "SCHEDULED"}]
    if branch:
        tasks = [row for row in tasks if row["branch"] == branch]
    if q:
        needle = q.casefold()
        tasks = [row for row in tasks if any(needle in str(row.get(key, "")).casefold() for key in ("full_name", "account_number", "customer_id"))]
    branches = list(db.branches.find({}, {"_id": 0}).sort("branch_name", 1))
    upcoming = [row for row in all_rows if row["kyc_status"] == "EXPIRING_SOON"][:8]
    expired = [row for row in all_rows if row["kyc_status"] == "EXPIRED"][:8]
    report: dict[str, dict[str, int]] = {}
    for row in all_rows:
        if row["rekyc_status"] not in {"PENDING", "SCHEDULED"}:
            continue
        summary = report.setdefault(row["branch"], {"pending": 0, "overdue": 0})
        summary["pending"] += 1
        summary["overdue"] += int(row["kyc_status"] == "EXPIRED")
    max_pending = max((value["pending"] for value in report.values()), default=1)
    for value in report.values():
        value["width"] = max(8, int(value["pending"] / max_pending * 100))
    joint_exceptions = []
    for account in db.accounts.find({"joint_account": True}):
        holders = [row for row in all_rows if row["account_number"] == account["account_number"]]
        if len(holders) > 1:
            joint_exceptions.append({"account_number": account["account_number"], "holders": holders})
    quality_issues = list(db.data_quality_issues.find({}).sort("updated_at", -1).limit(8))
    return render_page(request, "dashboard.html", db, {
        "stats": stats, "tasks": tasks, "branches": branches, "report": report,
        "upcoming": upcoming, "expired": expired, "joint_exceptions": joint_exceptions,
        "quality_issues": quality_issues, "window_days": warning,
        "warning_options": WARNING_DAY_OPTIONS, "selected_branch": branch, "search": q,
    })


@app.get("/queue", response_class=HTMLResponse, name="rekyc_queue")
def rekyc_queue(
    request: Request,
    db: Annotated[Database, Depends(get_db)],
    warning_days: str = str(DEFAULT_WARNING_DAYS),
    branch: str = "",
    status_filter: str = "",
    q: str = "",
):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    warning = safe_warning_days(warning_days)
    scan_expiring_kyc(db, warning)
    refresh_kyc_statuses(db, warning)
    all_rows = kyc_view_rows(db, warning)
    tasks = [row for row in all_rows if row["rekyc_status"] in {"PENDING", "SCHEDULED"}]
    if branch:
        tasks = [row for row in tasks if row["branch"] == branch]
    if status_filter in {"PENDING", "SCHEDULED"}:
        tasks = [row for row in tasks if row["rekyc_status"] == status_filter]
    if q:
        needle = q.casefold()
        tasks = [row for row in tasks if any(
            needle in str(row.get(key, "")).casefold()
            for key in ("full_name", "account_number", "customer_id", "branch")
        )]
    branches = list(db.branches.find({}, {"_id": 0}).sort("branch_name", 1))
    return render_page(request, "queue.html", db, {
        "tasks": tasks,
        "branches": branches,
        "selected_branch": branch,
        "selected_status": status_filter,
        "search": q,
        "warning_days": warning,
        "warning_options": WARNING_DAY_OPTIONS,
        "pending_count": db.rekyc_records.count_documents({"status": "PENDING"}),
        "scheduled_count": db.rekyc_records.count_documents({"status": "SCHEDULED"}),
        "pending": db.rekyc_records.count_documents({"status": {"$in": ["PENDING", "SCHEDULED"]}}),
    })


@app.get("/data", response_class=HTMLResponse, name="customer_data")
def customer_data(request: Request, db: Annotated[Database, Depends(get_db)], q: str = ""):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    warning = DEFAULT_WARNING_DAYS
    records = kyc_view_rows(db, warning)
    if q:
        needle = q.casefold()
        records = [row for row in records if any(needle in str(row.get(key, "")).casefold() for key in ("full_name", "account_number", "customer_id", "branch", "document_type"))]
    return render_page(request, "customer_data.html", db, {"records": records, "search": q})


@app.post("/id-photo/scan", name="scan_id_photo")
async def scan_uploaded_id_photo(
    request: Request,
    db: Annotated[Database, Depends(get_db)],
    photo: Annotated[UploadFile, File()],
    submitted_csrf: Annotated[str, Form(alias="csrf_token")],
):
    """Extract suggested fields from an ID photo without storing its image."""
    if session_required(request, db) is None:
        raise HTTPException(status_code=401, detail="Administrator sign-in is required.")
    verify_csrf(request, submitted_csrf)
    if photo.content_type not in ALLOWED_IMAGE_TYPES:
        await photo.close()
        raise HTTPException(status_code=400, detail="Upload a JPEG, PNG, or WebP image.")
    image_bytes = await photo.read(MAX_IMAGE_BYTES + 1)
    await photo.close()
    try:
        return await asyncio.to_thread(scan_id_photo, image_bytes)
    except PhotoScanError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.get("/admin", response_class=HTMLResponse, name="admin_dashboard")
def admin_dashboard(request: Request, db: Annotated[Database, Depends(get_db)]):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    issues = refresh_data_quality_issues(db)
    stats, _ = dashboard_statistics(db, DEFAULT_WARNING_DAYS)
    return render_page(request, "admin.html", db, {"issues": issues, "stats": stats})


@app.get("/reports", response_class=HTMLResponse, name="branch_report")
def branch_report(
    request: Request,
    db: Annotated[Database, Depends(get_db)],
    branch_id: str = "", kyc_status: str = "", document_type: str = "",
    rekyc_status: str = "", expiry_from: str = "", expiry_to: str = "",
    date_from: str = "", date_to: str = "", warning_days: str = str(DEFAULT_WARNING_DAYS),
):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    warning = safe_warning_days(warning_days)
    rows = matching_report_rows(
        db, warning, branch_id=branch_id, kyc_status=kyc_status,
        document_type=document_type, rekyc_status=rekyc_status,
        expiry_from=expiry_from, expiry_to=expiry_to, date_from=date_from, date_to=date_to,
    )
    branches = list(db.branches.find({}, {"_id": 0}).sort("branch_name", 1))
    doc_types = sorted(db.kyc_records.distinct("document_type"))
    return render_page(request, "report.html", db, {
        "rows": rows, "branches": branches, "doc_types": doc_types,
        "filters": {"branch_id": branch_id, "kyc_status": kyc_status, "document_type": document_type,
                    "rekyc_status": rekyc_status, "expiry_from": expiry_from,
                    "expiry_to": expiry_to, "date_from": date_from, "date_to": date_to,
                    "warning_days": warning},
        "warning_options": WARNING_DAY_OPTIONS,
        "kyc_statuses": ("VALID", "EXPIRING_SOON", "EXPIRED", "MISSING_DATA", "RE_KYC_SCHEDULED", "RE_KYC_COMPLETED"),
        "rekyc_statuses": ("PENDING", "SCHEDULED", "COMPLETED"),
    })


@app.post("/scan", name="scan")
def scan(request: Request, db: Annotated[Database, Depends(get_db)], submitted_csrf: Annotated[str, Form(alias="csrf_token")], warning_days: str = Form(str(DEFAULT_WARNING_DAYS))):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    verify_csrf(request, submitted_csrf)
    warning = safe_warning_days(warning_days)
    count = scan_expiring_kyc(db, warning)
    refresh_kyc_statuses(db, warning)
    add_flash(request, f"Expiry scan complete. {count} new re-KYC task{'s' if count != 1 else ''} created.")
    return RedirectResponse("/", status_code=303)


@app.post("/tasks/{task_id}/schedule", name="schedule_task")
def schedule_task(
    task_id: str, request: Request, db: Annotated[Database, Depends(get_db)],
    submitted_csrf: Annotated[str, Form(alias="csrf_token")], scheduled_date: str = Form(""),
    assigned_officer: str = Form(""),
):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    verify_csrf(request, submitted_csrf)
    task = db.rekyc_records.find_one({"rekyc_id": task_id, "status": {"$in": ["PENDING", "SCHEDULED"]}})
    if task is None:
        add_flash(request, "That open re-KYC task could not be found.", "error")
    else:
        appointment = parse_master_date(scheduled_date) if scheduled_date else date.today() + timedelta(days=7)
        if appointment is None:
            add_flash(request, "Enter a valid appointment date.", "error")
        else:
            db.rekyc_records.update_one({"rekyc_id": task_id}, {"$set": {
                "status": "SCHEDULED", "scheduled_date": as_utc_datetime(appointment),
                "assigned_officer": assigned_officer.strip(), "updated_at": datetime.now(timezone.utc),
            }})
            refresh_kyc_statuses(db, DEFAULT_WARNING_DAYS)
            add_flash(request, "Re-KYC appointment scheduled.")
    return RedirectResponse(request.headers.get("referer", "/"), status_code=303)


@app.post("/tasks/{task_id}/complete", name="complete_task")
def complete_task(
    task_id: str, request: Request, db: Annotated[Database, Depends(get_db)],
    submitted_csrf: Annotated[str, Form(alias="csrf_token")],
    new_expiry_date: str = Form(""),
):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    verify_csrf(request, submitted_csrf)
    task = db.rekyc_records.find_one({"rekyc_id": task_id, "status": {"$in": ["PENDING", "SCHEDULED"]}})
    if task is None:
        add_flash(request, "That open re-KYC task could not be found.", "error")
    else:
        expiry = parse_master_date(new_expiry_date)
        if expiry is None:
            add_flash(request, "Enter the new document expiry date before completing re-KYC.", "error")
        else:
            now = datetime.now(timezone.utc)
            db.rekyc_records.update_one({"rekyc_id": task_id}, {
                "$set": {"status": "COMPLETED", "completed_date": now, "updated_at": now},
                "$unset": {"active_task_key": ""},
            })
            db.kyc_records.update_one({"kyc_id": task["kyc_id"]}, {"$set": {
                "kyc_date": now, "kyc_date_raw": now.date().isoformat(),
                "expiry_date": as_utc_datetime(expiry), "expiry_date_raw": expiry.isoformat(),
                "last_updated": now,
            }})
            refresh_kyc_statuses(db, DEFAULT_WARNING_DAYS)
            refresh_data_quality_issues(db)
            add_flash(request, "Re-KYC marked complete and the renewed document saved.")
    return RedirectResponse("/", status_code=303)


@app.post("/holders", name="add_holder")
async def add_holder(request: Request, db: Annotated[Database, Depends(get_db)]):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    values = {
        "customer_id": str(form.get("customer_id", "")).strip(),
        "name": str(form.get("full_name", "")).strip(),
        "date_of_birth": str(form.get("dob_text", "")).strip(),
        "branch_id": str(form.get("branch_id", "")).strip() or str(form.get("branch", "")).strip().upper().replace(" ", "-"),
        "branch_name": str(form.get("branch", "")).strip(),
        "account_number": str(form.get("account_number", "")).strip(),
        "customer_type": str(form.get("customer_type", "INDIVIDUAL")).upper(),
        "document_type": str(form.get("document_type", "")).strip(),
        "document_number": str(form.get("document_number", "")).strip(),
        "issue_date": str(form.get("issue_date", "")).strip(),
        "expiry_date": str(form.get("expiry_date", "")).strip(),
        "kyc_date": str(form.get("kyc_date", "")).strip(),
    }
    try:
        payload = CustomerCreate(**values)
        make_customer_record(payload, db)
        add_flash(request, "Customer and individual KYC record added. Invalid source dates were preserved and flagged.")
    except ValidationError as error:
        add_flash(request, f"Check the customer fields: {error.errors()[0]['msg']}", "error")
    except DuplicateKeyError:
        add_flash(request, "Customer ID already exists. Each holder must have a unique customer ID.", "error")
    return RedirectResponse(request.headers.get("referer", "/data"), status_code=303)


@app.get("/reports/branch.csv", name="export_branch_report")
def export_branch_report(
    request: Request, db: Annotated[Database, Depends(get_db)],
    branch_id: str = "", kyc_status: str = "", document_type: str = "",
    rekyc_status: str = "", expiry_from: str = "", expiry_to: str = "",
    date_from: str = "", date_to: str = "", warning_days: str = str(DEFAULT_WARNING_DAYS),
):
    if session_required(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    rows = matching_report_rows(
        db, safe_warning_days(warning_days), branch_id=branch_id, kyc_status=kyc_status,
        document_type=document_type, rekyc_status=rekyc_status, expiry_from=expiry_from,
        expiry_to=expiry_to, date_from=date_from, date_to=date_to,
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Branch", "Account", "Customer ID", "Account holder", "DOB source", "Document", "Expiry date", "KYC status", "Re-KYC status", "Scheduled for"])
    for row in rows:
        writer.writerow([row["branch"], row["account_number"], row["customer_id"], row["full_name"], row["dob_text"], row["document_type"], row["expiry_date"] or row["expiry_date_raw"], row["kyc_status"], row["rekyc_status"], row["scheduled_for"]])
    return Response(
        output.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=branch-rekyc-report.csv"},
    )


# Admin-only REST API. Browser pages use the same MongoDB service functions and session auth.
@app.post("/api/v1/auth/token", response_model=TokenResponse, tags=["authentication"])
def issue_token(
    form: Annotated[OAuth2PasswordRequestForm, Depends()], db: Annotated[Database, Depends(get_db)]
):
    username = form.username.strip().lower()
    admin = db.admin_users.find_one({"username": username, "role": "admin"})
    if admin is None or not verify_password(form.password, admin.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Administrator username or password is incorrect.", headers={"WWW-Authenticate": "Bearer"})
    return TokenResponse(access_token=create_access_token(username))


@app.get("/api/v1/auth/me", tags=["authentication"])
def api_me(admin: Annotated[dict[str, Any], Depends(get_api_admin)]):
    return {"username": admin["username"], "role": "admin"}


@app.get("/api/v1/customers", response_model=CustomerPage, tags=["customers"])
def api_customers(
    db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
    q: str = "", branch_id: str = "", page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
):
    query: dict[str, Any] = {}
    if branch_id:
        query["branch_id"] = branch_id
    if q:
        import re
        escaped = re.escape(q.strip())
        query["$or"] = [{"name": {"$regex": escaped, "$options": "i"}}, {"customer_id": {"$regex": escaped, "$options": "i"}}, {"account_numbers": {"$regex": escaped, "$options": "i"}}]
    total = db.customers.count_documents(query)
    documents = list(db.customers.find(query, {"_id": 0, "customer_id": 1, "name": 1, "date_of_birth": 1, "dob_raw": 1, "dob_status": 1, "branch_id": 1, "branch_name": 1, "account_numbers": 1, "customer_type": 1}).sort("name", 1).skip((page - 1) * page_size).limit(page_size))
    return CustomerPage(items=json_safe(documents), page=page, page_size=page_size, total=total)


@app.post("/api/v1/customers", tags=["customers"], status_code=201)
def api_create_customer(
    payload: CustomerCreate, db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)]
):
    try:
        customer, kyc = make_customer_record(payload, db)
    except DuplicateKeyError as error:
        raise HTTPException(status_code=409, detail="Customer ID already exists.") from error
    kyc["document_number"] = mask_document_number(kyc.get("document_number", ""))
    return {"customer": json_safe(customer), "kyc_record": json_safe(kyc)}


@app.get("/api/v1/customers/{customer_id}", tags=["customers"])
def api_customer_detail(
    customer_id: str, db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)]
):
    customer = db.customers.find_one({"customer_id": customer_id}, {"_id": 0})
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found.")
    kyc_records = list(db.kyc_records.find({"customer_id": customer_id}, {"_id": 0}))
    for record in kyc_records:
        record["document_number"] = mask_document_number(record.get("document_number", ""))
    return {"customer": json_safe(customer), "kyc_records": json_safe(kyc_records)}


def paginated_kyc_response(rows: list[dict[str, Any]], page: int, page_size: int):
    return paginate(rows, page, page_size)


@app.get("/api/v1/kyc/status", tags=["kyc"])
def api_kyc_status(
    db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
    warning_days: Literal[30, 60, 90] = DEFAULT_WARNING_DAYS, branch_id: str = "",
    kyc_status: str = "", document_type: str = "", rekyc_status: str = "",
    expiry_from: str = "", expiry_to: str = "", page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
):
    rows = matching_report_rows(db, warning_days, branch_id=branch_id, kyc_status=kyc_status, document_type=document_type, rekyc_status=rekyc_status, expiry_from=expiry_from, expiry_to=expiry_to)
    return paginated_kyc_response(rows, page, page_size)


@app.get("/api/v1/kyc/expiring", tags=["kyc"])
def api_expiring_kyc(
    db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
    warning_days: Literal[30, 60, 90] = DEFAULT_WARNING_DAYS, branch_id: str = "",
    document_type: str = "", page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
):
    rows = [row for row in kyc_view_rows(db, warning_days, branch_id=branch_id, document_type=document_type) if row["kyc_status"] == "EXPIRING_SOON"]
    return paginated_kyc_response(rows, page, page_size)


@app.get("/api/v1/kyc/expired", tags=["kyc"])
def api_expired_kyc(
    db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
    warning_days: Literal[30, 60, 90] = DEFAULT_WARNING_DAYS, branch_id: str = "",
    document_type: str = "", page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
):
    rows = [row for row in kyc_view_rows(db, warning_days, branch_id=branch_id, document_type=document_type) if row["kyc_status"] == "EXPIRED"]
    return paginated_kyc_response(rows, page, page_size)


@app.get("/api/v1/dashboard/stats", tags=["dashboard"])
def api_dashboard_stats(
    db: Annotated[Database, Depends(get_db)],
    _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
    warning_days: Literal[30, 60, 90] = DEFAULT_WARNING_DAYS,
):
    refresh_data_quality_issues(db)
    refresh_kyc_statuses(db, warning_days)
    stats, _ = dashboard_statistics(db, warning_days)
    return {"warning_days": warning_days, **stats}


@app.get("/api/v1/reports/branches", tags=["reports"])
def api_branch_report(
    db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
    warning_days: Literal[30, 60, 90] = DEFAULT_WARNING_DAYS, branch_id: str = "",
    kyc_status: str = "", document_type: str = "", rekyc_status: str = "",
    expiry_from: str = "", expiry_to: str = "", date_from: str = "", date_to: str = "",
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
):
    rows = matching_report_rows(db, warning_days, branch_id=branch_id, kyc_status=kyc_status, document_type=document_type, rekyc_status=rekyc_status, expiry_from=expiry_from, expiry_to=expiry_to, date_from=date_from, date_to=date_to)
    report: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = report.setdefault(row["branch_id"], {"branch_id": row["branch_id"], "branch_name": row["branch"], "pending_count": 0, "overdue_count": 0, "customers": []})
        if row["rekyc_status"] in {"PENDING", "SCHEDULED"}:
            item["pending_count"] += 1
        if row["kyc_status"] == "EXPIRED":
            item["overdue_count"] += 1
        item["customers"].append(row)
    branches = list(report.values())
    return {"items": branches, "page": page, "page_size": page_size, "total": len(branches)}


@app.get("/api/v1/data-quality", tags=["data quality"])
def api_data_quality(
    db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
    issue_type: str = "", page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
):
    refresh_data_quality_issues(db)
    query = {"issue_type": issue_type} if issue_type else {}
    total = db.data_quality_issues.count_documents(query)
    items = list(db.data_quality_issues.find(query, {"_id": 0}).sort("updated_at", -1).skip((page - 1) * page_size).limit(page_size))
    return {"items": json_safe(items), "page": page, "page_size": page_size, "total": total}


@app.post("/api/v1/scan", tags=["kyc"])
def api_scan(
    db: Annotated[Database, Depends(get_db)],
    _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
    warning_days: Literal[30, 60, 90] = DEFAULT_WARNING_DAYS,
):
    created = scan_expiring_kyc(db, warning_days)
    refresh_kyc_statuses(db, warning_days)
    return {"created_tasks": created, "warning_days": warning_days}


@app.post("/api/v1/rekyc/{rekyc_id}/schedule", tags=["re-kyc"])
def api_schedule_rekyc(
    rekyc_id: str, payload: RekycScheduleRequest,
    db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
):
    task = db.rekyc_records.find_one({"rekyc_id": rekyc_id, "status": {"$in": ["PENDING", "SCHEDULED"]}})
    if task is None:
        raise HTTPException(status_code=404, detail="Open re-KYC task not found.")
    db.rekyc_records.update_one({"rekyc_id": rekyc_id}, {"$set": {
        "status": "SCHEDULED", "scheduled_date": as_utc_datetime(payload.scheduled_date),
        "assigned_officer": payload.assigned_officer, "remarks": payload.remarks,
        "updated_at": datetime.now(timezone.utc),
    }})
    refresh_kyc_statuses(db, DEFAULT_WARNING_DAYS)
    return {"message": "Re-KYC scheduled.", "rekyc_id": rekyc_id, "status": "SCHEDULED", "scheduled_date": payload.scheduled_date.isoformat()}


@app.post("/api/v1/rekyc/{rekyc_id}/complete", tags=["re-kyc"])
def api_complete_rekyc(
    rekyc_id: str, payload: RekycCompleteRequest,
    db: Annotated[Database, Depends(get_db)], _admin: Annotated[dict[str, Any], Depends(get_api_admin)],
):
    task = db.rekyc_records.find_one({"rekyc_id": rekyc_id, "status": {"$in": ["PENDING", "SCHEDULED"]}})
    if task is None:
        raise HTTPException(status_code=404, detail="Open re-KYC task not found.")
    completed = as_utc_datetime(payload.completed_date)
    update = {"status": "COMPLETED", "completed_date": completed, "remarks": payload.remarks, "updated_at": datetime.now(timezone.utc)}
    db.rekyc_records.update_one({"rekyc_id": rekyc_id}, {"$set": update, "$unset": {"active_task_key": ""}})
    kyc_update: dict[str, Any] = {"kyc_date": completed, "last_updated": datetime.now(timezone.utc)}
    kyc_update["expiry_date"] = as_utc_datetime(payload.new_expiry_date)
    kyc_update["expiry_date_raw"] = payload.new_expiry_date.isoformat()
    db.kyc_records.update_one({"kyc_id": task["kyc_id"]}, {"$set": kyc_update})
    refresh_data_quality_issues(db)
    refresh_kyc_statuses(db, DEFAULT_WARNING_DAYS)
    return {"message": "Re-KYC completed.", "rekyc_id": rekyc_id, "status": "COMPLETED"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
