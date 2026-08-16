---
title: SecureAccess Pro
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# SecureAccess Pro

**A Zero Trust Network Access Control System with Multi-Factor Authentication and Real-Time Monitoring Dashboard**

Final Year Project — Department of Cyber Security, Mehran University of Engineering & Technology (MUET), Batch 2022.

SecureAccess Pro acts as a Zero Trust gatekeeper in front of multiple internal
applications (HR Portal, Finance Dashboard, Document Manager). Every user is
authenticated with a password **and** a time-based one-time passcode (TOTP),
every request is verified server-side against a role-based access-control (RBAC)
policy, and every action is logged to a real-time security dashboard.

> "University security guards check student ID cards at the gate, monitor
> everything inside the campus, and stop students from other universities —
> only verified students can enter." — the project's own analogy for ZTNA.

---

## Core features (mapped to the seminar)

| Capability | Implementation |
|---|---|
| **Multi-Factor Authentication** | Password (bcrypt) **+** TOTP second factor (`pyotp`, 30-sec window) |
| **JWT sessions** | Short-lived tokens, **15-minute** configurable expiry, role claim embedded |
| **RBAC** | `Admin` / `User` / `Viewer` roles enforced by server-side middleware |
| **Brute-force protection** | Account **lockout after 3 consecutive failed attempts** |
| **Zero Trust monitoring** | Every request tracked; access decisions logged GRANTED/DENIED |
| **Real-time dashboard** | Admin GUI with KPI tiles + auto-refreshing logs (< 5s) |
| **Two GUIs** | End-user application + specialised admin security dashboard |
| **Patient Records (CRUD)** | 55 seeded records; read for Admin/User, **create/update/delete Admin-only** |
| **Tamper-evident audit log** | SHA-256 hash-chained entries; integrity verification detects any tampering |
| **Anomaly detection / alerts** | SOC-style alerts: brute-force, privilege probing, account lockouts |
| **Security hardening** | NIST-style password policy + API rate limiting (429) |

### Phase 2 — Risk-aware Zero Trust (advanced access control)

The system goes beyond static "login → MFA → RBAC → access". Every login **and**
every sensitive access is scored and re-evaluated by a policy engine:

```
Identity → MFA → Device → Context → Risk Score → Policy Engine
        → Access Decision → Continuous Monitoring → Automatic Response
```

| Upgrade | Implementation |
|---|---|
| **Risk-Based Access Control** | A risk score from live signals — failed attempts, new/unknown IP, unknown device, off-hours, account state, resource sensitivity — expressed on the **CVSS v3 severity scale** (None 0.0 / Low 0.1–3.9 / Medium 4.0–6.9 / High 7.0–8.9 / Critical 9.0–10.0) in `risk.py`. |
| **Device Trust** | Each browser carries a random, non-PII device id; a per-user fingerprint is trusted after full MFA. Unknown/untrusted devices raise risk; an admin can un-trust a device to force step-up (`models/zerotrust.py`, `TrustedDevice`). |
| **Continuous Verification** | Sensitive resources are re-scored on **every** request via a `continuous_verify` guard. MEDIUM → step-up (re-MFA), HIGH → session revoked automatically + alert. |
| **Real session revocation** | Each JWT is tracked in a `SessionToken` store and checked by a JWT blocklist loader, so a stateless token can be **killed mid-flight** — closing the classic "valid token after an account is blocked" gap. |
| **Policy engine** | Turns a risk band into an automatic decision: `ALLOW` / `STEP_UP` / `REVOKE`, all recorded to a `RiskEvent` audit trail. |
| **Risk & Policy dashboard** | New admin tab: active sessions (with one-click revoke), a live risk-decision feed, and device-trust management. |
| **Authenticator-app MFA** | TOTP (Google Authenticator / Authy) is a first-class second factor alongside email OTP; `provisioning_uri` returned at registration for QR enrolment. |

### Phase 3 — Secure File Upload + Automated Malware Detection

Zero Trust extended to **data itself**: an authenticated user may upload, but the
file is untrusted until scanned. Flow:

```
Auth + MFA -> RBAC + Continuous Verify -> Upload -> Validate -> SHA-256
 -> Secure temp -> Scan -> CLEAN: approved store  |  SUSPICIOUS/MALICIOUS: quarantine
                                                     + admin alert + Critical risk event
```

| Control | Implementation |
|---|---|
| **Upload guard** | `@roles_required(Admin, User)` **+** `@continuous_verify` — a blocked/high-risk session cannot upload even with a valid token; Viewers cannot upload. |
| **Validation** | Size cap (streamed), safe-filename + path-traversal rejection, random server-side names. **Every file type is accepted by default and left to the scanner** (`UPLOAD_ALLOW_ALL_TYPES=true`); set it `false` to restrict to a content-sniffed MIME allow-list (extension never trusted). |
| **Scanning** | Pluggable engine (`scanner.py`): **demo** = EICAR + structural heuristics (no deps); **clamav** = real signatures via the `clamd` daemon. Failures fail *closed* (SCAN_ERROR ⇒ quarantine). |
| **Quarantine** | Unsafe files moved to a private `backend/var/quarantine` dir (outside web root, non-executable, never served to users). |
| **Hashing** | SHA-256 per file for identification, audit and duplicate detection. |
| **Audit** | `FILE_UPLOAD_STARTED / FILE_UPLOADED / FILE_SCAN_* / FILE_QUARANTINED / FILE_ACCESS_GRANTED|DENIED / ADMIN_REVIEWED_FILE` — written to the **same hash-chained** audit stream. |
| **Alerts + risk** | A malicious upload surfaces in the existing **Security Alerts** and logs a **Critical** `RiskEvent`; optional `MALWARE_AUTO_BLOCK` (off by default). |
| **Admin monitor** | New **File Security** tab: metrics, recent detections with SHA-256, and review (approve suspicious / reject / keep quarantined). Malicious files can never be approved for download. |

New model `uploaded_files`. New files: `models/file.py`, `scanner.py`, `filevault.py`,
`routes/files.py`. **Optional deps** (real scanning): `pip install clamd` + a running
ClamAV daemon, and optionally `pip install python-magic` for stronger MIME detection;
set `SCANNER_MODE=clamav`. Test detection with the standard **EICAR** file — never real malware.

**Limitation:** signature-based scanning only detects *known* threats; a CLEAN result
means "no known signature matched", not "guaranteed safe". The demo engine is for
demonstration, not production antivirus coverage.

### Phase 4 — AI / UEBA adaptive risk (behaviour analytics)

Upgrades the risk engine from purely rule-based to **behaviour-aware**. A
per-user **User & Entity Behaviour Analytics** model learns each account's normal
login pattern and adds an **explainable** anomaly on top of the CVSS score.

| Aspect | Implementation |
|---|---|
| **Model** | Unsupervised per-user baseline (`ueba.py`, numpy): login-hour distribution, inter-login intervals, known IPs/devices. Optional **scikit-learn IsolationForest** engine (`UEBA_MODEL=iforest`, used only if installed). |
| **Signals** | Unusual login *hour for this user* (personal, not just generic off-hours) and login-burst velocity (possible automation). |
| **Explainable** | Every anomaly point carries a plain reason, e.g. *"unusual login hour 03:00 for this user (usual: 14:00)"* — shown live in the Risk Decision Feed. |
| **Cold-start safe** | Stays silent until `UEBA_MIN_LOGINS` logins are learned, so new accounts are never falsely flagged. |
| **Learning** | Each successful login folds into the profile (`observe_login`); admin is exempt from scoring. |
| **Dashboard** | New **Behaviour Analytics** panel on the Risk & Policy tab: logins learned, typical hours, known IPs/devices, last anomaly (CVSS) and Learning/Active state. |

New model `behavior_profiles`; new file `ueba.py`; new admin endpoint
`GET /api/behavior-profiles`. Optional dep: `pip install scikit-learn`.

**Limitation:** a lightweight behavioural model trained on small per-user data — a
demonstrator of adaptive/AI-driven risk, not an enterprise ML detection product.

### RBAC Role-Permission Matrix

| Feature | Admin | User | Viewer |
|---|:---:|:---:|:---:|
| Login + MFA (JWT + TOTP) | Yes | Yes | Yes |
| HR Portal | Yes | Yes | No |
| Finance Dashboard | Yes | No | No |
| Document Manager (read) | Yes | Yes | Yes |
| Admin Dashboard / Logs | Yes | No | No |
| Manage Users / Roles | Yes | No | No |

---

## Project structure

```
secureaccess-pro/
├── backend/                 # Flask REST API (the Zero Trust gateway)
│   ├── app.py               # application factory + request tracking
│   ├── config.py            # env-driven configuration
│   ├── extensions.py        # db + jwt instances
│   ├── security.py          # RBAC decorator + continuous-verify guard + audit
│   ├── risk.py              # Phase 2 risk engine + policy engine
│   ├── scanner.py          # Phase 3 malware scanner (demo / ClamAV)
│   ├── filevault.py        # Phase 3 upload validation + secure storage
│   ├── ueba.py             # Phase 4 behaviour analytics (AI adaptive risk)
│   ├── seed.py              # create Admin/User/Viewer demo accounts
│   ├── show_code.py         # print a user's current TOTP (demo helper)
│   ├── models/              # User, AccessLog, LoginHistory, SiteAccess,
│   │                        #   TrustedDevice, SessionToken, RiskEvent (Phase 2)
│   ├── routes/              # auth, resources, admin, patients, zerotrust (Phase 2)
│   ├── datastore.py         # loads the confidential data served by the apps
│   ├── data/                # confidential data behind the gateway (synthetic)
│   │   ├── hr/employees.json
│   │   ├── finance/financials.json
│   │   └── documents/*.txt
│   ├── patient_seed.py      # generates 55 synthetic patient records
│   └── requirements.txt
├── client/                  # Tkinter desktop GUIs
│   ├── api_client.py        # shared REST client
│   ├── user_app.py          # end-user application
│   └── admin_dashboard.py   # admin security dashboard
├── database/
│   └── schema.sql           # reference schema (auto-created by SQLAlchemy)
└── README.md
```

---

## Web version & deployment (public URL)

Besides the desktop GUIs, the backend also serves a **browser app** (login,
**Create Account**, MFA/email-OTP, role-based dashboard, admin monitoring &
patient management) at `/`. Run the backend and open `http://127.0.0.1:5000`
in a browser.

### Deploy to a public URL (Render.com — free)

1. Push this repo to GitHub (already done if you cloned it).
2. Go to <https://render.com> → sign up (free) → **New → Blueprint**.
3. Connect your GitHub and pick this repository. Render reads `render.yaml`
   and configures everything (build + start command).
4. Click **Apply**. In ~2 minutes you get a public URL like
   `https://secureaccess-pro.onrender.com` that anyone can open.

The app auto-seeds demo accounts + patients on first boot. To enable **real
email OTP**, add `SMTP_USER`, `SMTP_PASSWORD` (Gmail App Password) and
`SMTP_FROM` in Render → your service → **Environment**. (No `render.yaml`?
Any Python host works with the included `Procfile`.)

> Note: on the free tier the SQLite database resets when the instance sleeps.
> For persistent data, add a PostgreSQL database and set `DATABASE_URL`.

## Quick start (one command)

From the project root:

```bash
pip install -r backend/requirements.txt
python run.py
```

`run.py` seeds the database on first run, starts the backend, and opens a
launcher window with buttons for the **User Application** and the **Admin
Security Dashboard** — no separate terminals needed. On Windows you can instead
just double-click **`START.bat`**; on macOS/Linux run **`./run.sh`**.

## Manual start (step by step)

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Seed the demo accounts

```bash
python seed.py --reset
```

This creates three accounts, each with a unique TOTP secret, and prints their
provisioning URIs (add them to Google Authenticator / Authy) and the current
6-digit codes:

| Role   | Username       | Password          |
|--------|----------------|-------------------|
| Admin  | `Abdul Rehman` | `AbdulRehman2711` |
| User   | `user`         | `User@123`        |
| Viewer | `viewer`       | `Viewer@123`      |

### 3. Run the backend

```bash
python app.py      # http://127.0.0.1:5000  (SQLite by default)
```

### 4. Run a GUI

```bash
cd ../client
python user_app.py          # end-user application
python admin_dashboard.py   # admin security dashboard (Admin login only)
```

> **Getting the MFA code without a phone:** run
> `python backend/show_code.py admin` to print the current TOTP for a user.

---

## Multi-factor authentication (email OTP + TOTP)

Login requires a second factor. You can use **either**:

- **Email OTP** — click **"Email me a code"** on the login screen (or call
  `POST /api/request-otp`). A 6-digit code is emailed to the user's registered
  address and is valid for 5 minutes, one-time use.
- **Authenticator TOTP** — the code from an authenticator app / `show_code.py`.

**Enabling real email (Gmail):** set these in `backend/.env` —

```
SMTP_USER=your-gmail@gmail.com
SMTP_PASSWORD=your-16-char-app-password   # Google Account > Security > App passwords
SMTP_FROM=your-gmail@gmail.com
```

> Use a Gmail **App Password**, not your normal password (requires 2-Step
> Verification on the Google account). Without SMTP configured, the system runs
> in **dev mode**: the code is printed to the server console and shown in the
> app so it stays demoable.

## Configuration

The backend runs on **SQLite** with zero configuration. Copy
`backend/.env.example` to `backend/.env` to customise the JWT secret, token
lifetime, TOTP window, lockout policy, or to point at **PostgreSQL** via
`DATABASE_URL`.

---

## REST API

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/login` | — | Password + OTP (email or TOTP) → JWT |
| `POST` | `/api/request-otp` | — | Email a one-time login code to the user |
| `POST` | `/api/register` | — | Self-service signup (defaults to Viewer) |
| `GET` | `/api/protected/hr` | Admin, User | HR Portal |
| `GET` | `/api/protected/finance` | Admin | Finance Dashboard |
| `GET` | `/api/protected/patients` | Admin, User | List patient records (55 seeded) |
| `GET` | `/api/protected/patients/<pid>` | Admin, User | Read one patient |
| `POST` | `/api/protected/patients` | **Admin only** | Create a patient |
| `PUT` | `/api/protected/patients/<pid>` | **Admin only** | Update a patient |
| `DELETE` | `/api/protected/patients/<pid>` | **Admin only** | Delete a patient |
| `GET` | `/api/protected/documents` | Admin, User, Viewer | Document Manager |
| `GET` | `/api/logs` | Admin | Access / audit logs |
| `GET` | `/api/login-history` | Admin | Authentication history |
| `GET` | `/api/site-access` | Admin | Raw request tracking |
| `GET` | `/api/metrics` | Admin | Dashboard KPI counters |
| `GET` | `/api/alerts` | Admin | Real-time security alerts (anomaly detection) |
| `GET` | `/api/audit/verify` | Admin | Verify the tamper-evident audit chain |
| `GET` | `/api/users` | Admin | List users |
| `PUT` | `/api/users/<id>/role` | Admin | Change a user's role |
| `POST` | `/api/users/<id>/unlock` | Admin | Clear a lockout |
| `GET` | `/api/export/<dataset>` | Admin | Download audit CSV (`access-logs` / `login-history` / `site-access`) |

## Tests

```bash
cd backend
python -m pytest tests/ -q
```

The suite covers MFA (password + TOTP), the RBAC matrix for each role,
brute-force lockout after 3 failed attempts, and admin-only CSV export.

---

## Threat model coverage

- **Brute-force / credential stuffing** — lockout after 3 failures + mandatory TOTP.
- **Token replay** — TOTP codes are time-bound (30-sec window).
- **Session hijacking** — short-lived 15-minute JWTs.
- **Privilege escalation** — RBAC enforced server-side; roles can't be self-modified.
- **Lateral movement** — each app independently enforces its own access policy.
- **Insider misuse** — all actions logged and surfaced on the admin dashboard.

---

*Built for the SecureAccess Pro Final Year Project — MUET, Department of Cyber Security.*
