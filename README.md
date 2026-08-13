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

### RBAC Role-Permission Matrix

| Feature | Admin | User | Viewer |
|---|:---:|:---:|:---:|
| Login + MFA (JWT + TOTP) | ✅ | ✅ | ✅ |
| HR Portal | ✅ | ✅ | ❌ |
| Finance Dashboard | ✅ | ❌ | ❌ |
| Document Manager (read) | ✅ | ✅ | ✅ |
| Admin Dashboard / Logs | ✅ | ❌ | ❌ |
| Manage Users / Roles | ✅ | ❌ | ❌ |

---

## Project structure

```
secureaccess-pro/
├── backend/                 # Flask REST API (the Zero Trust gateway)
│   ├── app.py               # application factory + request tracking
│   ├── config.py            # env-driven configuration
│   ├── extensions.py        # db + jwt instances
│   ├── security.py          # RBAC decorator + audit logging
│   ├── seed.py              # create Admin/User/Viewer demo accounts
│   ├── show_code.py         # print a user's current TOTP (demo helper)
│   ├── models/              # User, AccessLog, LoginHistory, SiteAccess
│   ├── routes/              # auth, resources (RBAC apps), admin (monitoring)
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
