from __future__ import annotations

import os
import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from pymongo import ASCENDING, DESCENDING, MongoClient

from services import as_utc_datetime, parse_master_date
from security import hash_password

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DATABASE = os.environ.get("MONGODB_DATABASE", "kyc_watch")
_client: MongoClient | None = None
_test_database = None


def get_database():
    global _client
    if _test_database is not None:
        return _test_database
    if _client is None:
        _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000, tz_aware=True)
    return _client[MONGODB_DATABASE]


def set_test_database(database) -> None:
    global _test_database
    _test_database = database


def initialize_database(db, *, seed_demo: bool | None = None) -> None:
    db.customers.create_index([("customer_id", ASCENDING)], unique=True)
    db.customers.create_index([("branch_id", ASCENDING), ("name", ASCENDING)])
    db.accounts.create_index([("account_number", ASCENDING)], unique=True)
    db.kyc_records.create_index([("kyc_id", ASCENDING)], unique=True)
    db.kyc_records.create_index([("customer_id", ASCENDING), ("expiry_date", ASCENDING)])
    db.kyc_records.create_index([("expiry_date", ASCENDING)])
    db.rekyc_records.create_index([("rekyc_id", ASCENDING)], unique=True)
    db.rekyc_records.create_index([("active_task_key", ASCENDING)], unique=True, sparse=True)
    db.rekyc_records.create_index([("branch_id", ASCENDING), ("status", ASCENDING), ("scheduled_date", ASCENDING)])
    db.branches.create_index([("branch_id", ASCENDING)], unique=True)
    db.admin_users.create_index([("username", ASCENDING)], unique=True)
    db.data_quality_issues.create_index([("issue_id", ASCENDING)], unique=True)

    should_seed = seed_demo if seed_demo is not None else os.environ.get("KYC_SEED_DEMO", "true").lower() == "true"
    if db.customers.count_documents({}) == 0 and should_seed:
        seed_demo_data(db)
    bootstrap_admin(db)


def bootstrap_admin(db) -> None:
    username = os.environ.get("KYC_ADMIN_USERNAME", "").strip().lower()
    password = os.environ.get("KYC_ADMIN_PASSWORD", "")
    if os.environ.get("KYC_DEMO_ADMIN", "false").lower() == "true":
        username = username or "admin"
        password = password or "admin"
        logging.warning("Insecure demo administrator enabled. Do not use these credentials outside local development.")
    if username and password and db.admin_users.find_one({"username": username}) is None:
        db.admin_users.insert_one({
            "username": username,
            "password_hash": hash_password(password),
            "role": "admin",
            "created_at": datetime.now(timezone.utc),
        })


def seed_demo_data(db) -> None:
    """Insert masked demo records; each customer owns their own KYC timeline."""
    today = date.today()
    now = datetime.now(timezone.utc)
    branches = [
        {"branch_id": "BR-IND", "branch_name": "Indiranagar", "location": "Bengaluru", "manager_name": "Demo Manager", "status": "ACTIVE"},
        {"branch_id": "BR-WFD", "branch_name": "Whitefield", "location": "Bengaluru", "manager_name": "Demo Manager", "status": "ACTIVE"},
        {"branch_id": "BR-KRM", "branch_name": "Koramangala", "location": "Bengaluru", "manager_name": "Demo Manager", "status": "ACTIVE"},
        {"branch_id": "BR-JYN", "branch_name": "Jayanagar", "location": "Bengaluru", "manager_name": "Demo Manager", "status": "ACTIVE"},
    ]
    db.branches.insert_many(branches)
    rows = [
        ("CIF-10041", "Aarav Mehta", "14/08/1987", "VALID", "BR-IND", "Indiranagar", "AC-204819", "Passport", "P•••7821", 18, "14/08/2025"),
        ("CIF-10042", "Mira Mehta", "1989-03-22", "VALID", "BR-IND", "Indiranagar", "AC-204819", "National ID", "ID•••1954", 46, "2025-03-22"),
        ("CIF-10058", "Ishaan Rao", "05-11-1975", "VALID", "BR-WFD", "Whitefield", "AC-351207", "Driving licence", "DL•••6208", -9, "05-11-2024"),
        ("CIF-10103", "Nisha Kapoor", "31/02/1993", "INVALID", "BR-KRM", "Koramangala", "AC-487116", "Passport", "P•••4480", 74, "2025-12-01"),
        ("CIF-10124", "Dev Shah", "17/02/1968", "VALID", "BR-WFD", "Whitefield", "AC-593882", "National ID", "ID•••3312", 5, "17/02/2025"),
        ("CIF-10139", "Leela Iyer", "1979-06-30", "VALID", "BR-JYN", "Jayanagar", "AC-610445", "Passport", "P•••9037", -21, "1979-06-30"),
    ]
    for customer_id, name, dob_raw, dob_status, branch_id, branch_name, account_number, document_type, document_number, days_to_expiry, kyc_raw in rows:
        dob = parse_master_date(dob_raw)
        expiry = today + timedelta(days=days_to_expiry)
        kyc_date = parse_master_date(kyc_raw)
        db.customers.insert_one({
            "customer_id": customer_id,
            "name": name,
            "date_of_birth": as_utc_datetime(dob),
            "dob_raw": dob_raw,
            "dob_status": dob_status if dob else "INVALID",
            "branch_id": branch_id,
            "branch_name": branch_name,
            "account_numbers": [account_number],
            "customer_type": "JOINT" if account_number == "AC-204819" else "INDIVIDUAL",
            "created_at": now,
            "updated_at": now,
        })
        kyc_id = f"KYC-{customer_id}"
        db.kyc_records.insert_one({
            "kyc_id": kyc_id,
            "customer_id": customer_id,
            "account_number": account_number,
            "document_type": document_type,
            "document_number": document_number,
            "issue_date": None,
            "expiry_date": as_utc_datetime(expiry),
            "expiry_date_raw": expiry.isoformat(),
            "kyc_date": as_utc_datetime(kyc_date),
            "kyc_date_raw": kyc_raw,
            "status": "ACTIVE",
            "last_updated": now,
        })
        db.accounts.update_one(
            {"account_number": account_number},
            {"$setOnInsert": {
                "account_number": account_number,
                "branch_id": branch_id,
                "account_type": "JOINT" if account_number == "AC-204819" else "SAVINGS",
                "joint_account": account_number == "AC-204819",
                "status": "ACTIVE",
                "created_at": now,
            }, "$addToSet": {"holder_ids": customer_id}},
            upsert=True,
        )
