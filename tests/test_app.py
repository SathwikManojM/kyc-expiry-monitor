import io
import os
import re
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

from PIL import Image, ImageDraw, ImageFont

import mongomock
from fastapi.testclient import TestClient

import app as kyc_app
import database
from migrate_sqlite import migrate
from id_photo_scan import extract_id_fields, scan_id_photo
from security import hash_password, verify_password
from services import calculate_kyc_status, parse_master_date, refresh_data_quality_issues, scan_expiring_kyc


class KycMonitorTests(unittest.TestCase):
    def setUp(self):
        self.mongo_client = mongomock.MongoClient(tz_aware=True)
        self.db = self.mongo_client["kyc_watch_test"]
        database.set_test_database(self.db)
        self.client = TestClient(kyc_app.app)
        self.client.__enter__()
        self.db.admin_users.insert_one({
            "username": "admin", "password_hash": hash_password("strong-test-password"),
            "role": "admin",
        })
        login_page = self.client.get("/login")
        csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text).group(1)
        login = self.client.post("/login", data={
            "username": "admin", "password": "strong-test-password", "csrf_token": csrf_token,
        }, follow_redirects=False)
        self.assertEqual(login.status_code, 303)
        token_response = self.client.post("/api/v1/auth/token", data={
            "username": "admin", "password": "strong-test-password",
        })
        self.api_token = token_response.json()["access_token"]
        self.api_headers = {"Authorization": f"Bearer {self.api_token}"}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        database.set_test_database(None)
        self.mongo_client.close()

    def test_dob_parser_supports_three_formats_and_rejects_invalid_dates(self):
        expected = date(1987, 8, 14)
        self.assertEqual(parse_master_date("14/08/1987"), expected)
        self.assertEqual(parse_master_date("14-08-1987"), expected)
        self.assertEqual(parse_master_date("1987-08-14"), expected)
        self.assertIsNone(parse_master_date("31/02/1987"))
        self.assertIsNone(parse_master_date("not a date"))

    def test_login_is_admin_only_and_public_registration_is_disabled(self):
        anonymous = TestClient(kyc_app.app)
        with anonymous:
            self.assertEqual(anonymous.get("/", follow_redirects=False).status_code, 303)
            self.assertEqual(anonymous.get("/register").status_code, 404)
            self.assertEqual(anonymous.get("/api/v1/customers").status_code, 401)

    def test_opt_in_demo_credentials_are_stored_as_password_hash(self):
        demo_db = mongomock.MongoClient(tz_aware=True)["demo_admin_test"]
        with patch.dict("os.environ", {
            "KYC_DEMO_ADMIN": "true", "KYC_ADMIN_USERNAME": "", "KYC_ADMIN_PASSWORD": "",
        }):
            database.initialize_database(demo_db, seed_demo=False)
        account = demo_db.admin_users.find_one({"username": "admin"})
        self.assertIsNotNone(account)
        self.assertNotEqual(account["password_hash"], "admin")
        self.assertTrue(verify_password("admin", account["password_hash"]))

    def test_dashboard_renders_requested_compliance_sections(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        for title in (b"TOTAL CUSTOMERS", b"EXPIRED KYC", b"EXPIRING SOON", b"Branch-wise pending re-KYC", b"Joint-account holder exceptions", b"Data-quality issues"):
            self.assertIn(title, response.content)
        self.assertEqual(self.client.get("/data").status_code, 200)
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_sidebar_highlight_follows_each_page_route(self):
        for path in ("/", "/data", "/queue", "/reports", "/admin"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.text.count('class="nav-link active"'), 1)
                self.assertEqual(response.text.count('aria-current="page"'), 1)
                if path == "/queue":
                    self.assertIn("Re-KYC follow-up", response.text)
                    self.assertIn("Open re-KYC tasks", response.text)

    def test_joint_holders_keep_separate_kyc_documents_and_expiry_dates(self):
        holders = list(self.db.customers.find({"account_numbers": "AC-204819"}))
        records = list(self.db.kyc_records.find({"account_number": "AC-204819"}))
        self.assertEqual(len(holders), 2)
        self.assertEqual(len(records), 2)
        self.assertEqual(len({row["customer_id"] for row in records}), 2)
        self.assertNotEqual(records[0]["expiry_date"], records[1]["expiry_date"])

    def test_invalid_source_dates_are_preserved_and_flagged(self):
        payload = {
            "customer_id": "CIF-DQ-1", "name": "Data Check", "date_of_birth": "31/02/1993",
            "branch_id": "BR-IND", "branch_name": "Indiranagar", "account_number": "AC-DQ-1",
            "customer_type": "INDIVIDUAL", "document_type": "Passport", "document_number": "P1234567",
            "issue_date": "", "expiry_date": "not-a-date", "kyc_date": "",
        }
        response = self.client.post("/api/v1/customers", json=payload, headers=self.api_headers)
        self.assertEqual(response.status_code, 201)
        customer = self.db.customers.find_one({"customer_id": "CIF-DQ-1"})
        kyc = self.db.kyc_records.find_one({"customer_id": "CIF-DQ-1"})
        self.assertEqual(customer["dob_raw"], "31/02/1993")
        self.assertIsNone(customer["date_of_birth"])
        self.assertEqual(kyc["expiry_date_raw"], "not-a-date")
        issues = refresh_data_quality_issues(self.db)
        self.assertGreaterEqual(sum(issue["customer_id"] == "CIF-DQ-1" for issue in issues), 3)

    def test_scan_is_idempotent_and_tasks_are_holder_level(self):
        first_pending = self.db.rekyc_records.count_documents({"status": "PENDING"})
        self.assertGreater(first_pending, 0)
        self.assertEqual(scan_expiring_kyc(self.db, 60), 0)
        self.assertEqual(self.db.rekyc_records.count_documents({"status": "PENDING"}), first_pending)

    def test_schedule_and_complete_rekyc_updates_records(self):
        task = self.db.rekyc_records.find_one({"status": "PENDING"})
        scheduled = self.client.post(
            f"/api/v1/rekyc/{task['rekyc_id']}/schedule",
            json={"scheduled_date": (date.today() + timedelta(days=5)).isoformat(), "assigned_officer": "Officer A"},
            headers=self.api_headers,
        )
        self.assertEqual(scheduled.status_code, 200)
        self.assertEqual(scheduled.json()["status"], "SCHEDULED")
        complete = self.client.post(
            f"/api/v1/rekyc/{task['rekyc_id']}/complete",
            json={"completed_date": date.today().isoformat(), "new_expiry_date": (date.today() + timedelta(days=365)).isoformat()},
            headers=self.api_headers,
        )
        self.assertEqual(complete.status_code, 200)
        saved_task = self.db.rekyc_records.find_one({"rekyc_id": task["rekyc_id"]})
        saved_kyc = self.db.kyc_records.find_one({"kyc_id": task["kyc_id"]})
        self.assertEqual(saved_task["status"], "COMPLETED")
        self.assertNotIn("active_task_key", saved_task)
        self.assertIsNotNone(saved_kyc["kyc_date"])
        self.assertEqual(saved_kyc["expiry_date"].date(), date.today() + timedelta(days=365))

    def test_api_auth_pagination_filters_and_sensitive_number_masking(self):
        unauthorized = self.client.get("/api/v1/customers")
        self.assertEqual(unauthorized.status_code, 401)
        customers = self.client.get("/api/v1/customers?page=1&page_size=2", headers=self.api_headers)
        self.assertEqual(customers.status_code, 200)
        self.assertEqual(customers.json()["page_size"], 2)
        self.assertEqual(len(customers.json()["items"]), 2)
        detail = self.client.get("/api/v1/customers/CIF-10041", headers=self.api_headers)
        self.assertEqual(detail.status_code, 200)
        self.assertNotIn("P•••7821", detail.text)
        self.assertEqual(self.client.get("/api/v1/dashboard/stats?warning_days=45", headers=self.api_headers).status_code, 422)

    def test_branch_report_filters_and_csv_export(self):
        report = self.client.get("/api/v1/reports/branches?branch_id=BR-IND", headers=self.api_headers)
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.json()["total"], 1)
        page = self.client.get("/reports?branch_id=BR-IND")
        self.assertEqual(page.status_code, 200)
        export = self.client.get("/reports/branch.csv?branch_id=BR-IND")
        self.assertEqual(export.status_code, 200)
        self.assertIn(b"CIF-10041", export.content)
        self.assertIn(b"CIF-10042", export.content)

    def test_csrf_required_for_html_mutation(self):
        response = self.client.post("/scan", data={"csrf_token": "wrong", "warning_days": "60"})
        self.assertEqual(response.status_code, 400)

    def test_id_photo_ocr_extracts_labeled_fields_without_returning_raw_text(self):
        fields = extract_id_fields("""PASSPORT
Name: Jordan Sample
Passport No: X1234567
Date of Birth: 12/04/1990
Date of Issue: 05/06/2020
Date of Expiry: 05/06/2030
""")
        self.assertEqual(fields["full_name"], "Jordan Sample")
        self.assertEqual(fields["dob_text"], "1990-04-12")
        self.assertEqual(fields["document_type"], "Passport")
        self.assertEqual(fields["document_number"], "X1234567")
        self.assertEqual(fields["expiry_date"], "2030-06-05")
        self.assertNotIn("raw_text", fields)

    def test_id_photo_ocr_accepts_labeled_synthetic_demo_card(self):
        fields = extract_id_fields("""KYC TEST RECORD - SOFTWARE DEMO - FICTIONAL
Name: Aarav Malik
Date of Birth: 05/11/1995
Document Type: SYNTHETIC ID CARD
Document No: DEMO-0001-330
Issue Date: 17/02/2022
Expiry Date: 17/02/2027
SAMPLE - NOT A REAL ID
""")
        self.assertEqual(fields["full_name"], "Aarav Malik")
        self.assertEqual(fields["dob_text"], "1995-11-05")
        self.assertEqual(fields["document_type"], "SYNTHETIC ID CARD")
        self.assertEqual(fields["document_number"], "DEMO-0001-330")
        self.assertEqual(fields["issue_date"], "2022-02-17")
        self.assertEqual(fields["expiry_date"], "2027-02-17")

    def test_real_tesseract_reads_diagonal_sample_watermark(self):
        tesseract = os.environ.get("TESSERACT_CMD", r"C:\Program Files\Tesseract-OCR\tesseract.exe")
        if not Path(tesseract).is_file():
            self.skipTest("Tesseract OCR engine is not installed")
        image_stream = io.BytesIO()
        image = Image.new("RGB", (1000, 480), "white")
        draw = ImageDraw.Draw(image)
        font = ImageFont.truetype(r"C:\Windows\Fonts\arialbd.ttf", 34)
        for index, text in enumerate((
            "KYC TEST RECORD - SOFTWARE DEMO FICTIONAL", "Name: Aarav Malik",
            "Date of Birth: 05/11/1995", "Document Type: SYNTHETIC ID CARD",
            "Document No: DEMO-0001-330", "Issue Date: 17/02/2022", "Expiry Date: 17/02/2027",
        )):
            draw.text((55, 25 + index * 61), text, fill="black", font=font)
        watermark = Image.new("RGBA", (850, 100), (0, 0, 0, 0))
        watermark_draw = ImageDraw.Draw(watermark)
        watermark_draw.text((8, 4), "SAMPLE - NOT A REAL ID", font=font, fill=(120, 120, 120, 72))
        watermark = watermark.rotate(22, expand=True)
        image = image.convert("RGBA")
        image.alpha_composite(watermark, (80, 120))
        image.convert("RGB").save(image_stream, format="PNG")

        with patch.dict(os.environ, {"TESSERACT_CMD": ""}):
            result = scan_id_photo(image_stream.getvalue())
        self.assertEqual(result["fields"]["full_name"], "Aarav Malik")
        self.assertEqual(result["fields"]["document_type"], "SYNTHETIC ID CARD")
        self.assertEqual(result["fields"]["document_number"], "DEMO-0001-330")
        self.assertEqual(result["fields"]["expiry_date"], "2027-02-17")

    def test_photo_scan_requires_admin_csrf_and_valid_image(self):
        anonymous = TestClient(kyc_app.app)
        with anonymous:
            response = anonymous.post(
                "/id-photo/scan", data={"csrf_token": "any"},
                files={"photo": ("id.png", b"not an image", "image/png")},
            )
            self.assertEqual(response.status_code, 401)

        page = self.client.get("/data")
        csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = self.client.post(
            "/id-photo/scan",
            data={"csrf_token": csrf_token},
            files={"photo": ("id.png", b"not an image", "image/png")},
        )
        self.assertEqual(response.status_code, 400)

    def test_photo_scan_returns_suggestions_from_ephemeral_upload(self):
        image_stream = io.BytesIO()
        Image.new("RGB", (64, 40), color="white").save(image_stream, format="PNG")
        page = self.client.get("/data")
        csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        with patch(
            "pytesseract.image_to_string",
            return_value="Passport\nName: Jordan Sample\nDate of Birth: 12/04/1990\nDate of Expiry: 05/06/2030",
        ):
            response = self.client.post(
                "/id-photo/scan",
                data={"csrf_token": csrf_token},
                files={"photo": ("id.png", image_stream.getvalue(), "image/png")},
            )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["fields"]["full_name"], "Jordan Sample")
        self.assertEqual(result["fields"]["expiry_date"], "2030-06-05")
        self.assertTrue(result["review_required"])
        self.assertNotIn("recognized_text", result)

        response = self.client.post(
            "/id-photo/scan", data={"csrf_token": "invalid"},
            files={"photo": ("id.png", b"not an image", "image/png")},
        )
        self.assertEqual(response.status_code, 400)

    def test_status_logic_prioritizes_task_state_and_warning_window(self):
        expiry = date.today() + timedelta(days=10)
        kyc = {"expiry_date": expiry, "kyc_date": date.today()}
        self.assertEqual(calculate_kyc_status(kyc, None, 30), "EXPIRING_SOON")
        self.assertEqual(calculate_kyc_status(kyc, None, 30), "EXPIRING_SOON")
        self.assertEqual(calculate_kyc_status(kyc, {"status": "SCHEDULED"}, 30), "RE_KYC_SCHEDULED")
        self.assertEqual(calculate_kyc_status({"expiry_date": None, "kyc_date": None}, None, 30), "MISSING_DATA")

    def test_sqlite_migration_preserves_joint_holders_and_flags_absent_kyc_dates(self):
        migration_db = mongomock.MongoClient(tz_aware=True)["isolated_migration_test"]
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "legacy.db"
            legacy = sqlite3.connect(source)
            legacy.executescript("""
                CREATE TABLE account_holders (
                    id INTEGER PRIMARY KEY, account_number TEXT, customer_id TEXT,
                    full_name TEXT, dob_text TEXT, branch TEXT, phone TEXT, created_at TEXT
                );
                CREATE TABLE kyc_documents (
                    id INTEGER PRIMARY KEY, holder_id INTEGER, document_type TEXT,
                    document_number TEXT, expiry_date TEXT, verified_at TEXT
                );
                CREATE TABLE rekyc_tasks (
                    id INTEGER PRIMARY KEY, document_id INTEGER, status TEXT,
                    due_date TEXT, scheduled_for TEXT, created_at TEXT
                );
            """)
            legacy.executemany(
                "INSERT INTO account_holders VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (1, "ACC-LEGACY", "LEG-1", "Joint One", "01/01/1980", "Legacy", "", "2026-01-01 00:00:00"),
                    (2, "ACC-LEGACY", "LEG-2", "Joint Two", "1981-02-03", "Legacy", "", "2026-01-01 00:00:00"),
                ],
            )
            legacy.executemany(
                "INSERT INTO kyc_documents VALUES (?, ?, ?, ?, ?, ?)",
                [(11, 1, "Passport", "P•••11", "2030-01-01", None), (12, 2, "Passport", "P•••12", "2031-01-01", None)],
            )
            legacy.execute(
                "INSERT INTO rekyc_tasks VALUES (?, ?, ?, ?, ?, ?)",
                (21, 11, "Scheduled", "2030-01-01", "2026-10-01", "2026-01-02 00:00:00"),
            )
            legacy.commit()
            legacy.close()

            database.set_test_database(migration_db)
            try:
                imported = migrate(source)
            finally:
                database.set_test_database(self.db)

        self.assertEqual(imported, (2, 2, 1))
        account = migration_db.accounts.find_one({"account_number": "ACC-LEGACY"})
        self.assertTrue(account["joint_account"])
        self.assertEqual(set(account["holder_ids"]), {"LEG-1", "LEG-2"})
        self.assertIsNone(migration_db.kyc_records.find_one({"kyc_id": "KYC-LEGACY-11"})["kyc_date"])
        self.assertEqual(migration_db.rekyc_records.find_one({"rekyc_id": "RK-LEGACY-21"})["status"], "SCHEDULED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
