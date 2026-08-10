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

## Quick start

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

| Role   | Username | Password    |
|--------|----------|-------------|
| Admin  | `admin`  | `Admin@123` |
| User   | `user`   | `User@123`  |
| Viewer | `viewer` | `Viewer@123`|

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

## Configuration

The backend runs on **SQLite** with zero configuration. Copy
`backend/.env.example` to `backend/.env` to customise the JWT secret, token
lifetime, TOTP window, lockout policy, or to point at **PostgreSQL** via
`DATABASE_URL`.

---

## REST API

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/login` | — | Password + TOTP → JWT |
| `POST` | `/api/register` | — | Self-service signup (defaults to Viewer) |
| `GET` | `/api/protected/hr` | Admin, User | HR Portal |
| `GET` | `/api/protected/finance` | Admin | Finance Dashboard |
| `GET` | `/api/protected/documents` | Admin, User, Viewer | Document Manager |
| `GET` | `/api/logs` | Admin | Access / audit logs |
| `GET` | `/api/login-history` | Admin | Authentication history |
| `GET` | `/api/site-access` | Admin | Raw request tracking |
| `GET` | `/api/metrics` | Admin | Dashboard KPI counters |
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
