# MRITYUNJAY — AI-Powered Cybersecurity for Emergency Healthcare Networks

A runnable full-stack demonstration based on Team NAVKRITI's proposal. It combines emergency resource discovery with protected medical records, role-based authorization, signed JWTs, AES-256-GCM encryption, audit trails and anomaly scoring.

## Implemented modules

- Patient registration/login and role-aware navigation (Patient, Hospital Staff, Ambulance Operator, Admin).
- Verified hospital directory, specialty/city search and hospital-reported ICU/general/oxygen bed counts.
- Hospital staff/admin bed availability updates and hospital profile creation API.
- Ambulance directory, emergency request creation, assignment to an available vehicle and request status API.
- Verified donor directory, blood-group/city filtering, donor registration and donor connection requests.
- Emergency contact hub with click-to-call links.
- Encrypted medical record creation, listing and authorized retrieval.
- Admin SOC dashboard with audit events, failed-login throttling, alert resolution and controlled intrusion simulation.
- SQLite persistence, PBKDF2-SHA256 password hashes, HMAC-SHA256 signed JWTs and AES-256-GCM record encryption.
- Scikit-learn IsolationForest-assisted anomaly scoring with deterministic risk rules.

## Requirements

- Python 3.10+
- `cryptography`
- `scikit-learn` (optional at runtime; if unavailable, the server uses its deterministic risk rules)

This prototype intentionally uses Python's standard-library HTTP server and `sqlite3` so it runs without a Flask/ORM service dependency. The REST API and data layer are separated by clear route and schema boundaries. SQLite is selected for a portable local demo; a production deployment should migrate to PostgreSQL/MySQL and use a managed secret store.

## Setup

### Windows (PowerShell)

```powershell
cd mrityunjay
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
py server.py
```

### macOS / Linux

```bash
cd mrityunjay
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python server.py
```

Open **http://localhost:8000**. The SQLite database is created automatically at `instance/mrityunjay.db` and seeded on first run. Records persist when the server restarts.

## Demo credentials

| Role | Email | Password |
|---|---|---|
| Patient | `patient@mrityunjay.demo` | `Patient@123` |
| Hospital Staff | `hospital@mrityunjay.demo` | `Hospital@123` |
| Ambulance Operator | `ambulance@mrityunjay.demo` | `Ambulance@123` |
| Admin / SOC | `admin@mrityunjay.demo` | `Admin@123` |

Change all demo passwords and secrets before any deployment. Sample hospitals, donors, phone numbers and contact details are illustrative only; they are not live verified emergency resources.

## API overview

All API routes return JSON. Protected endpoints require `Authorization: Bearer <token>`.

| Method | Endpoint | Access |
|---|---|---|
| GET | `/api/health` | Public |
| POST | `/api/auth/register` | Public (patient/hospital/ambulance self-registration) |
| POST | `/api/auth/login` | Public |
| GET | `/api/auth/me` | Authenticated |
| GET | `/api/dashboard` | Authenticated |
| GET / POST | `/api/hospitals` | Public read / Hospital or Admin create |
| PATCH | `/api/beds` | Hospital or Admin |
| GET | `/api/ambulances` | Public |
| GET / POST | `/api/ambulance-requests` | Authenticated read / Patient or Admin create |
| PATCH | `/api/ambulance-requests/{id}` | Ambulance Operator or Admin |
| GET / POST | `/api/donors` | Public read / Patient or Admin register |
| POST | `/api/donor-requests` | Patient or Admin |
| GET | `/api/contacts` | Public |
| GET / POST | `/api/records` | Patient/Hospital/Admin with patient ownership checks |
| GET | `/api/records/{id}` | Patient/Hospital/Admin with patient ownership checks |
| GET | `/api/security/overview` | Admin |
| POST | `/api/security/simulate` | Admin |
| PATCH | `/api/security/alerts/{id}` | Admin |

## Data and security notes

- Passwords are PBKDF2-HMAC-SHA256 hashed with per-user random salts (240,000 iterations).
- JWTs are HMAC-SHA256 signed and expire after 10 hours. The demo client stores the token in localStorage; production should prefer secure, HttpOnly, SameSite cookies.
- Medical record payloads use AES-256-GCM with a fresh 96-bit nonce per record. The encryption key is derived from `DATA_ENCRYPTION_KEY`; protect and rotate it outside the database.
- Failed login attempts are audited and trigger a temporary throttle after five failures in a rolling 15-minute window.
- The SOC demo includes a controlled simulation action. It does not execute real attacks or claim real-time network packet inspection.
- HTTPS/TLS must be terminated by a production reverse proxy (for example, Caddy or Nginx). The local demo uses HTTP on localhost.
- Emergency contacts and demo resources must be independently verified before real-world use. This is not a certified clinical system and does not dispatch real ambulances.

## Tests

Run the built-in smoke tests:

```bash
python tests/smoke_test.py
```

The tests start an isolated server/database, verify health, login, role restrictions, hospital discovery, record encryption/decryption, ambulance request persistence and SOC alert simulation.
