# KYC Watch — KYC Document Expiry Monitor for Bank Branches

**Project:** 24CC3071-P003
**Stack:** FastAPI, MongoDB, PyMongo, Pydantic, Jinja2

KYC Watch is an admin/compliance-officer-only application for tracking customer-level KYC documents, expiry risk, re-KYC follow-up, branch reports, and source-data quality. The existing dashboard design and server-rendered UI are retained and now use FastAPI routes backed by MongoDB.

> Demo software only. Never enter real customer PII, account data, or identity-document information. It is not a production banking system.

## Features

- Admin-only sign-in; no customer accounts and no public registration page.
- Argon2 password hashes, signed administrator sessions, CSRF protection for browser form actions, and bearer-token protection for REST APIs.
- MongoDB collections for customers, accounts, individual KYC records, re-KYC history, branches, administrators, and data-quality issues.
- DOB and KYC date parsing for `DD/MM/YYYY`, `DD-MM-YYYY`, and `YYYY-MM-DD`. Original text is preserved; invalid/missing values become reviewable data-quality issues.
- Individual KYC timelines for every holder, including holders sharing a joint account.
- KYC statuses: `VALID`, `EXPIRING_SOON`, `EXPIRED`, `MISSING_DATA`, `RE_KYC_SCHEDULED`, and `RE_KYC_COMPLETED`.
- Configurable warning window: 30, 60, or 90 days (60 by default), selectable in the dashboard.
- Dashboard summaries, branch pending chart, upcoming/expired worklists, joint-account holder view, and data-quality review.
- Filterable branch report and CSV export.
- Customer search, account-linked customer data, task scheduling/completion, and idempotent expiry scans.
- Optional ID-photo upload with local OCR suggestions to prefill holder/document fields. The application does not retain uploaded photos; staff must verify every extracted value. Multipart parsing may use temporary buffering.
- Pydantic request validation, pagination, and REST API documentation at `/docs`.

## Setup (Windows PowerShell)

### 1. Prepare Python

Use Python 3.10+ and install the application dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 2. Start or configure MongoDB

Use a local MongoDB Community Server or a MongoDB Atlas database. Set the connection string and application secret in the same PowerShell session used to run the app:

```powershell
$env:MONGODB_URI = "mongodb://localhost:27017"
$env:MONGODB_DATABASE = "kyc_watch"
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:KYC_SECRET_KEY = [Convert]::ToBase64String($bytes)
$env:KYC_SEED_DEMO = "true"
$env:KYC_EXPIRY_WARNING_DAYS = "60"
```

For Atlas, set `MONGODB_URI` to the connection string from your Atlas deployment instead. Keep credentials out of source control and use a database user with only the required database permissions.

### Optional: enable ID-photo OCR

The photo scanner requires the Tesseract OCR executable in addition to the Python packages. On Windows, install the Tesseract OCR engine using your approved package source/installer, then restart the app. If it is not on `PATH`, set its executable path before starting:

```powershell
$env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
```

In **Customer data → Add customer**, choose or capture a JPEG, PNG, or WebP image up to 5 MB and select **Upload & scan**. OCR only returns suggested name/type/number/date fields; it does not decide whether an identity document is genuine or valid. Check each value against the image before saving. The application does not persist the photo or OCR text. The multipart parser may temporarily buffer an upload and discards it when the request closes. This demo should not be used to process real identity documents.

### 3. Create the administrator

There is deliberately no web registration. Create the initial administrator from the setup utility; it prompts for a password without echoing it and requires at least 12 characters:

```powershell
python admin_cli.py create-admin --username compliance-admin
```

Alternatively, set both `KYC_ADMIN_USERNAME` and `KYC_ADMIN_PASSWORD` before the first app startup to bootstrap an administrator. Prefer the interactive CLI for local setup so a password is not stored in shell history.

For this local demo only, setting `$env:KYC_DEMO_ADMIN = "true"` before the first startup creates the login `admin` / `admin`. This is intentionally disabled by default and is unsafe outside a private development machine. If an admin already exists, the demo bootstrap does not overwrite it.

### 4. Run KYC Watch

```powershell
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000> and sign in with the provisioned administrator credentials. FastAPI's interactive API reference is at <http://127.0.0.1:8000/docs>.

The first startup creates MongoDB indexes, optionally inserts masked demo data, scans for expiring records, and refreshes data-quality/KYC statuses. Set `KYC_SEED_DEMO=false` to disable sample records for a new database. The warning period can be set to `30`, `60`, or `90` using `KYC_EXPIRY_WARNING_DAYS`.

## Where to view backend data

- **Inside the app:** sign in, open **Customer data** to browse holder and KYC records, and open **Data quality** to review source-date issues.
- **In MongoDB:** the database defaults to `kyc_watch`. Collections and key relationships:

| Collection | Purpose and key fields |
| --- | --- |
| `customers` | One document per holder: `customer_id`, `name`, normalized BSON `date_of_birth`, original `dob_raw`, `dob_status`, `branch_id`, `branch_name`, `account_numbers`, `customer_type`. |
| `accounts` | One document per account: `account_number`, `branch_id`, `holder_ids`, `joint_account`, `status`. |
| `kyc_records` | One record per holder/document: `kyc_id`, `customer_id`, `account_number`, `document_type`, `document_number`, normalized dates plus original source text, computed `status`. |
| `rekyc_records` | Re-KYC history per individual KYC record: `rekyc_id`, `kyc_id`, `customer_id`, scheduled/completed dates, assigned officer, remarks, status. |
| `branches` | Branch reference data: `branch_id`, `branch_name`, location, manager, status. |
| `admin_users` | Admin-only credentials; passwords are stored as Argon2 hashes. |
| `data_quality_issues` | Current invalid/missing DOB, expiry, and KYC-date issues, with field and original source value. |

KYC dates and documents are always linked to `customer_id`/`kyc_id`, not just an account number. Thus two holders on one joint account can have different KYC dates, expiry dates, statuses, and follow-up records.

## REST API

All `/api/v1` data endpoints require an administrator bearer token. Obtain a token with the OAuth2 password form at `POST /api/v1/auth/token`; use `Authorization: Bearer <access_token>` for subsequent calls. Requests are validated with Pydantic, and list/report APIs provide bounded pagination.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/auth/token`, `GET /api/v1/auth/me` | Admin authentication and current principal |
| `GET/POST /api/v1/customers` | Search/list with branch and pagination; create customer + KYC record |
| `GET /api/v1/customers/{customer_id}` | Customer detail and associated KYC records |
| `GET /api/v1/kyc/status` | Filtered calculated KYC statuses |
| `GET /api/v1/kyc/expiring`, `GET /api/v1/kyc/expired` | Expiring/expired documents |
| `POST /api/v1/scan` | Run idempotent expiry scan |
| `POST /api/v1/rekyc/{rekyc_id}/schedule` | Schedule a re-KYC task |
| `POST /api/v1/rekyc/{rekyc_id}/complete` | Complete task; optionally save the new document expiry date |
| `GET /api/v1/reports/branches` | Branch report with branch, status, document, expiry, re-KYC, and date filters |
| `GET /api/v1/dashboard/stats` | Dashboard totals for the selected 30/60/90 day period |
| `GET /api/v1/data-quality` | Paginated data-quality issues |

## Existing SQLite data migration

The original Flask version stored records in `instance/kyc_monitor.db`. To import those customer, account, document, and task records into the configured MongoDB database, first back up the SQLite file, configure `MONGODB_URI`, then run:

```powershell
python migrate_sqlite.py
```

Set `KYC_LEGACY_SQLITE` if the source file is elsewhere. The migration is safe to rerun and does not seed demo customers. The old schema did not contain a KYC date, so migrated KYC dates remain missing and are reported as data-quality issues; the migration never substitutes DOB for KYC date.

## Tests

The suite uses `mongomock` for an isolated MongoDB-compatible test database:

```powershell
python -m unittest discover -s tests -v
```

Tests cover admin-only access, DOB parsing and invalid-date preservation, joint-holder independence, scan idempotency, KYC status logic, customer/API pagination, report filters, password login, CSRF checks, and scheduling/completion.

## Security note

The dashboard is a local/student demo, not suitable for handling real banking data. Before deployment, use TLS, a strong managed `KYC_SECRET_KEY`, `KYC_COOKIE_SECURE=true`, a restricted MongoDB user, rate limiting, audit logging, encryption/key management, backups, retention policies, monitoring, and an institution-specific security/compliance review. Do not use the built-in development secret or demo records in production.
