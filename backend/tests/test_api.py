"""
End-to-end API tests for SecureAccess Pro: MFA, RBAC matrix, and lockout.
"""

from conftest import login, token_for, auth_header


# --------------------------------------------------------------------------- #
# Authentication + MFA
# --------------------------------------------------------------------------- #
def test_login_requires_valid_totp(client, totp_for):
    # Correct password but wrong TOTP -> rejected.
    resp = login(client, "admin", "Admin@123", "000000")
    assert resp.status_code == 401

    # Correct password + correct TOTP -> token issued.
    resp = login(client, "admin", "Admin@123", totp_for("admin"))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["role"] == "Admin"
    assert body["expires_in_minutes"] == 15
    assert body["token"]


def test_wrong_password_rejected(client, totp_for):
    resp = login(client, "admin", "wrong-password", totp_for("admin"))
    assert resp.status_code == 401


def test_unknown_user_rejected(client):
    resp = login(client, "ghost", "whatever", "123456")
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# RBAC matrix
# --------------------------------------------------------------------------- #
def test_admin_can_reach_everything(client, totp_for):
    t = token_for(client, totp_for, "admin", "Admin@123")
    h = auth_header(t)
    assert client.get("/api/protected/hr", headers=h).status_code == 200
    assert client.get("/api/protected/finance", headers=h).status_code == 200
    assert client.get("/api/protected/documents", headers=h).status_code == 200
    assert client.get("/api/logs", headers=h).status_code == 200
    assert client.get("/api/metrics", headers=h).status_code == 200


def test_user_role_matrix(client, totp_for):
    t = token_for(client, totp_for, "user", "User@123")
    h = auth_header(t)
    assert client.get("/api/protected/hr", headers=h).status_code == 200        # allowed
    assert client.get("/api/protected/documents", headers=h).status_code == 200  # allowed
    assert client.get("/api/protected/finance", headers=h).status_code == 403    # denied
    assert client.get("/api/logs", headers=h).status_code == 403                 # denied


def test_viewer_role_matrix(client, totp_for):
    t = token_for(client, totp_for, "viewer", "Viewer@123")
    h = auth_header(t)
    assert client.get("/api/protected/documents", headers=h).status_code == 200  # allowed
    assert client.get("/api/protected/hr", headers=h).status_code == 403         # denied
    assert client.get("/api/protected/finance", headers=h).status_code == 403    # denied
    assert client.get("/api/protected/patients", headers=h).status_code == 403   # denied


def test_patient_records_access(client, totp_for):
    # Admin and User can read patient records; Viewer cannot.
    admin = auth_header(token_for(client, totp_for, "admin", "Admin@123"))
    user = auth_header(token_for(client, totp_for, "user", "User@123"))
    assert client.get("/api/protected/patients", headers=admin).status_code == 200
    resp = client.get("/api/protected/patients", headers=user)
    assert resp.status_code == 200
    assert "patients" in resp.get_json()


def test_patient_crud_admin_only(client, totp_for):
    admin = auth_header(token_for(client, totp_for, "admin", "Admin@123"))
    user = auth_header(token_for(client, totp_for, "user", "User@123"))
    viewer = auth_header(token_for(client, totp_for, "viewer", "Viewer@123"))
    new = {"name": "Test Case", "age": 50, "gender": "M", "diagnosis": "Sepsis",
           "severity": "Critical", "department": "ICU", "status": "ICU"}

    # Non-admins cannot create/update/delete.
    assert client.post("/api/protected/patients", json=new, headers=user).status_code == 403
    assert client.post("/api/protected/patients", json=new, headers=viewer).status_code == 403

    # Admin can create.
    created = client.post("/api/protected/patients", json=new, headers=admin)
    assert created.status_code == 201
    pid = created.get_json()["patient"]["patient_id"]

    # Non-admin update/delete blocked; admin update/delete allowed.
    assert client.put(f"/api/protected/patients/{pid}",
                      json={"severity": "Stable"}, headers=user).status_code == 403
    assert client.delete(f"/api/protected/patients/{pid}", headers=viewer).status_code == 403
    assert client.put(f"/api/protected/patients/{pid}",
                      json={"severity": "Stable"}, headers=admin).status_code == 200
    assert client.delete(f"/api/protected/patients/{pid}", headers=admin).status_code == 200


def test_patient_seed_has_many_records(client, totp_for):
    admin = auth_header(token_for(client, totp_for, "admin", "Admin@123"))
    body = client.get("/api/protected/patients", headers=admin).get_json()
    assert body["summary"]["total_patients"] >= 50


def test_protected_route_requires_token(client):
    assert client.get("/api/protected/hr").status_code == 401


# --------------------------------------------------------------------------- #
# Email OTP second factor
# --------------------------------------------------------------------------- #
def test_email_otp_login(client):
    # Request an OTP (dev mode returns the code since no SMTP is configured).
    resp = client.post("/api/request-otp",
                       json={"username": "admin", "password": "Admin@123"})
    assert resp.status_code == 200
    code = resp.get_json()["dev_code"]

    # Logging in with the emailed code (no TOTP) issues a token.
    ok = client.post("/api/login",
                     json={"username": "admin", "password": "Admin@123", "tfa_code": code})
    assert ok.status_code == 200

    # The code is one-time: reusing it fails.
    again = client.post("/api/login",
                        json={"username": "admin", "password": "Admin@123", "tfa_code": code})
    assert again.status_code == 401


def test_request_otp_does_not_leak_on_wrong_password(client):
    resp = client.post("/api/request-otp",
                       json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 200
    assert "dev_code" not in resp.get_json()  # no code generated for bad credentials


# --------------------------------------------------------------------------- #
# Tamper-evident audit log (hash chain)
# --------------------------------------------------------------------------- #
def test_audit_chain_intact_then_detects_tampering(client, totp_for, app):
    admin = auth_header(token_for(client, totp_for, "admin", "Admin@123"))
    # Generate a few audit entries.
    client.get("/api/protected/hr", headers=admin)
    client.get("/api/protected/finance", headers=admin)

    intact = client.get("/api/audit/verify", headers=admin).get_json()
    assert intact["intact"] is True

    # Tamper with a stored log row directly, then re-verify.
    from extensions import db
    from models import AccessLog
    with app.app_context():
        row = AccessLog.query.order_by(AccessLog.id.asc()).offset(1).first()
        row.status = "HACKED"
        db.session.commit()

    broken = client.get("/api/audit/verify", headers=admin).get_json()
    assert broken["intact"] is False
    assert broken["broken_at"] is not None


# --------------------------------------------------------------------------- #
# Anomaly detection / security alerts
# --------------------------------------------------------------------------- #
def test_alerts_flag_bruteforce(client, totp_for):
    # Three failed logins should raise a brute-force alert.
    for _ in range(3):
        client.post("/api/login",
                    json={"username": "viewer", "password": "WRONG", "tfa_code": "0"})
    admin = auth_header(token_for(client, totp_for, "admin", "Admin@123"))
    alerts = client.get("/api/alerts", headers=admin).get_json()["alerts"]
    types = {a["type"] for a in alerts}
    assert any("Brute-force" in t for t in types)


# --------------------------------------------------------------------------- #
# Password policy + rate limiting
# --------------------------------------------------------------------------- #
def test_password_policy_rejects_weak(client):
    weak = client.post("/api/register", json={
        "username": "weaky", "email": "w@x.com",
        "password": "abcdefg", "confirm_password": "abcdefg"})
    assert weak.status_code == 400  # too short / missing classes

    strong = client.post("/api/register", json={
        "username": "strongy", "email": "s@x.com",
        "password": "Abcdef1@", "confirm_password": "Abcdef1@"})
    assert strong.status_code == 201


def test_rate_limiting_returns_429(client, app):
    app.config["RATE_LIMIT_MAX"] = 4
    ok = 0
    limited = 0
    for _ in range(7):
        r = client.post("/api/login",
                        json={"username": "x", "password": "y", "tfa_code": "0"})
        if r.status_code == 429:
            limited += 1
        else:
            ok += 1
    assert ok == 4 and limited == 3


# --------------------------------------------------------------------------- #
# Brute-force lockout
# --------------------------------------------------------------------------- #
def test_lockout_after_three_failures(client, totp_for):
    for _ in range(3):
        assert login(client, "viewer", "WRONG", "000000").status_code == 401
    # Account is now locked: even the correct credentials are refused with 423.
    resp = login(client, "viewer", "Viewer@123", totp_for("viewer"))
    assert resp.status_code == 423
    assert "locked" in resp.get_json()["error"].lower()


# --------------------------------------------------------------------------- #
# Audit CSV export
# --------------------------------------------------------------------------- #
def test_export_csv_admin_only(client, totp_for):
    admin = auth_header(token_for(client, totp_for, "admin", "Admin@123"))
    resp = client.get("/api/export/access-logs", headers=admin)
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert b"timestamp" in resp.data  # header row present

    viewer = auth_header(token_for(client, totp_for, "viewer", "Viewer@123"))
    assert client.get("/api/export/access-logs", headers=viewer).status_code == 403


# --------------------------------------------------------------------------- #
# Phase 2 — Risk-Based Access Control, Device Trust, Continuous Verification
# --------------------------------------------------------------------------- #
def _login_dev(client, totp_for, username, password, device="dev-1"):
    """Log in with a device id; return (token, headers-incl-device)."""
    resp = client.post("/api/login", json={
        "username": username, "password": password,
        "tfa_code": totp_for(username), "device_id": device})
    body = resp.get_json()
    headers = {"Authorization": f"Bearer {body['token']}", "X-Device-Id": device}
    return resp, headers


def test_login_returns_risk_assessment(client, totp_for):
    # A non-admin user is scored; a brand-new device is not yet trusted.
    resp, _ = _login_dev(client, totp_for, "user", "User@123")
    risk = resp.get_json()["risk"]
    assert risk["level"] in ("LOW", "MEDIUM", "HIGH")
    assert isinstance(risk["score"], int)
    assert risk["known_device"] is False


def test_admin_is_exempt_from_risk_scoring(client, totp_for):
    # The administrator is the trusted authority — never risk-flagged.
    resp, ah = _login_dev(client, totp_for, "admin", "Admin@123")
    risk = resp.get_json()["risk"]
    assert risk["level"] == "LOW"
    assert risk["score"] == 0
    assert risk["known_device"] is True
    # And sensitive access is always allowed for the admin.
    assert client.get("/api/protected/finance", headers=ah).status_code == 200
    assert client.get("/api/protected/patients", headers=ah).status_code == 200


def test_continuous_verify_revokes_session_when_user_blocked(client, totp_for):
    # User logs in and can reach the HR portal.
    _, uh = _login_dev(client, totp_for, "user", "User@123", device="user-dev")
    assert client.get("/api/protected/hr", headers=uh).status_code == 200

    # Admin blocks the user mid-session.
    _, ah = _login_dev(client, totp_for, "admin", "Admin@123", device="admin-dev")
    assert client.post("/api/users/user/block", headers=ah).status_code == 200

    # The user's still-valid token is now revoked by continuous verification.
    revoked = client.get("/api/protected/hr", headers=uh)
    assert revoked.status_code == 403
    assert revoked.get_json()["session_revoked"] is True

    # And the token is globally dead — even a non-sensitive route is refused.
    assert client.get("/api/protected/documents", headers=uh).status_code == 401


def test_admin_can_revoke_a_live_session(client, totp_for):
    _, uh = _login_dev(client, totp_for, "user", "User@123", device="user-dev")
    _, ah = _login_dev(client, totp_for, "admin", "Admin@123", device="admin-dev")

    sessions = client.get("/api/sessions", headers=ah).get_json()
    user_session = next(s for s in sessions if s["username"] == "user")
    assert client.post(f"/api/sessions/{user_session['id']}/revoke",
                       headers=ah).status_code == 200

    # The user's token no longer works.
    assert client.get("/api/protected/documents", headers=uh).status_code == 401


def test_untrust_device_forces_step_up(client, totp_for):
    _, uh = _login_dev(client, totp_for, "user", "User@123", device="user-dev")
    _, ah = _login_dev(client, totp_for, "admin", "Admin@123", device="admin-dev")

    # Admin un-trusts the user's device.
    devices = client.get("/api/devices", headers=ah).get_json()
    dev = next(d for d in devices if d["username"] == "user")
    assert client.post(f"/api/devices/{dev['id']}/untrust", headers=ah).status_code == 200

    # The user's next sensitive access is scored MEDIUM -> step-up required.
    resp = client.get("/api/protected/hr", headers=uh)
    assert resp.status_code == 401
    assert resp.get_json()["step_up_required"] is True


def test_logout_revokes_own_session(client, totp_for):
    _, uh = _login_dev(client, totp_for, "user", "User@123", device="user-dev")
    assert client.post("/api/logout", headers=uh).status_code == 200
    # Token is dead after logout (real revocation on a stateless JWT).
    assert client.get("/api/protected/documents", headers=uh).status_code == 401


def test_risk_endpoints_are_admin_only(client, totp_for):
    viewer = auth_header(token_for(client, totp_for, "viewer", "Viewer@123"))
    for path in ("/api/risk-events", "/api/sessions", "/api/risk-metrics", "/api/devices"):
        assert client.get(path, headers=viewer).status_code == 403
