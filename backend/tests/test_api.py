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


def test_login_returns_cvss_risk_assessment(client, totp_for):
    # A non-admin user is scored on the CVSS severity scale.
    resp, _ = _login_dev(client, totp_for, "user", "User@123")
    risk = resp.get_json()["risk"]
    assert risk["level"] in ("None", "Low", "Medium", "High", "Critical")
    assert 0.0 <= risk["cvss"] <= 10.0
    assert risk["known_device"] is False


def test_admin_is_exempt_from_risk_scoring(client, totp_for):
    # The administrator is the trusted authority — never risk-flagged (CVSS None).
    resp, ah = _login_dev(client, totp_for, "admin", "Admin@123")
    risk = resp.get_json()["risk"]
    assert risk["level"] == "None"
    assert risk["cvss"] == 0.0
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


# --------------------------------------------------------------------------- #
# Secure File Upload + Malware Detection
# --------------------------------------------------------------------------- #
import io  # noqa: E402

# The official EICAR anti-malware test string (harmless), split to avoid flags.
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
         b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def _upload(client, headers, content, filename, device="dev-1"):
    h = dict(headers); h["X-Device-Id"] = device
    return client.post("/api/files/upload", headers=h,
                       data={"file": (io.BytesIO(content), filename)},
                       content_type="multipart/form-data")


def test_clean_file_is_scanned_and_downloadable(client, totp_for):
    _, uh = _login_dev(client, totp_for, "user", "User@123")
    r = _upload(client, uh, b"This is a perfectly clean report.\n", "report.txt")
    assert r.status_code == 201
    body = r.get_json()
    assert body["blocked"] is False
    assert body["file"]["scan_status"] == "CLEAN"
    # The owner can download a clean, approved file.
    assert client.get(f"/api/files/{body['file']['id']}/download", headers=uh).status_code == 200


def test_eicar_is_detected_quarantined_and_alerted(client, totp_for):
    _, uh = _login_dev(client, totp_for, "user", "User@123")
    r = _upload(client, uh, EICAR, "invoice.txt")
    assert r.status_code == 201
    body = r.get_json()
    assert body["blocked"] is True
    assert body["file"]["scan_status"] == "MALICIOUS"
    fid = body["file"]["id"]

    # The malicious file cannot be downloaded by the user.
    assert client.get(f"/api/files/{fid}/download", headers=uh).status_code == 403

    # A security alert is raised for the admin, and the audit chain stays intact.
    _, ah = _login_dev(client, totp_for, "admin", "Admin@123", device="admin-d")
    alerts = client.get("/api/alerts", headers=ah).get_json()["alerts"]
    assert any(a["type"] == "Malicious file upload" for a in alerts)
    assert client.get("/api/audit/verify", headers=ah).get_json()["intact"] is True


def test_upload_rejects_oversized_file(client, totp_for, app):
    app.config["MAX_UPLOAD_BYTES"] = 1024
    _, uh = _login_dev(client, totp_for, "user", "User@123")
    r = _upload(client, uh, b"A" * 2048, "big.txt")
    assert r.status_code == 400
    assert "limit" in r.get_json()["error"].lower()


def test_upload_rejects_path_traversal_name(client, totp_for):
    _, uh = _login_dev(client, totp_for, "user", "User@123")
    r = _upload(client, uh, b"x", "../../etc/passwd")
    assert r.status_code == 400


def test_upload_rejects_disallowed_content(client, totp_for):
    # A PE/EXE header is not in the MIME allow-list (extension is never trusted).
    _, uh = _login_dev(client, totp_for, "user", "User@123")
    r = _upload(client, uh, b"MZ\x90\x00 program bytes", "tool.bin")
    assert r.status_code == 400


def test_viewer_cannot_upload(client, totp_for):
    _, vh = _login_dev(client, totp_for, "viewer", "Viewer@123")
    r = _upload(client, vh, b"clean", "v.txt")
    assert r.status_code == 403  # RBAC: viewers may not upload


def test_user_cannot_download_another_users_file(client, totp_for):
    _, uh = _login_dev(client, totp_for, "user", "User@123", device="u1")
    fid = _upload(client, uh, b"private clean data", "mine.txt", device="u1").get_json()["file"]["id"]
    # A viewer (different account, no upload rights) must not reach the file.
    _, vh = _login_dev(client, totp_for, "viewer", "Viewer@123", device="v1")
    assert client.get(f"/api/files/{fid}/download", headers=vh).status_code == 403


def test_admin_can_review_quarantined_file(client, totp_for):
    _, uh = _login_dev(client, totp_for, "user", "User@123")
    fid = _upload(client, uh, EICAR, "bad.txt").get_json()["file"]["id"]
    _, ah = _login_dev(client, totp_for, "admin", "Admin@123", device="admin-d")
    # A malicious file cannot be approved for download.
    approve = client.post(f"/api/admin/files/{fid}/review", headers=ah, json={"decision": "approve"})
    assert approve.status_code == 400
    # But it can be explicitly rejected.
    reject = client.post(f"/api/admin/files/{fid}/review", headers=ah, json={"decision": "reject"})
    assert reject.status_code == 200
    assert reject.get_json()["file"]["review_status"] == "REJECTED"


# --------------------------------------------------------------------------- #
# UEBA — AI/behaviour-based adaptive risk
# --------------------------------------------------------------------------- #
def test_ueba_learns_and_is_quiet_at_cold_start(client, totp_for, app):
    # First login: no baseline yet -> UEBA must not flag ("still training").
    resp, _ = _login_dev(client, totp_for, "user", "User@123", device="u")
    assert not any("unusual login hour" in f for f in resp.get_json()["risk"]["factors"])
    # A profile is created and learns the login.
    from models import BehaviorProfile
    with app.app_context():
        p = BehaviorProfile.query.filter_by(username="user").first()
        assert p is not None and p.login_count >= 1


def test_ueba_flags_unusual_hour_after_baseline(client, totp_for, app):
    import ueba
    from datetime import datetime, timedelta
    from models import BehaviorProfile
    from extensions import db as _db
    # Seed a baseline: many past logins concentrated at 14:00 (2 PM).
    with app.app_context():
        p = BehaviorProfile(username="user")
        hist = [0] * 24
        hist[14] = 20
        p.set_hist(hist)
        p.login_count = 20
        p.set_intervals([86400] * 10)
        p.last_login_at = datetime.utcnow() - timedelta(hours=1)
        _db.session.add(p)
        _db.session.commit()
        # Evaluate a login "now" — if the current hour isn't 14:00 it should flag.
        score, factors = ueba.evaluate("user")
    if datetime.utcnow().hour != 14:
        assert score > 0
        assert any("unusual login hour" in f for f in factors)


def test_behavior_profiles_endpoint_admin_only(client, totp_for):
    _, ah = _login_dev(client, totp_for, "admin", "Admin@123", device="a")
    assert client.get("/api/behavior-profiles", headers=ah).status_code == 200
    viewer = auth_header(token_for(client, totp_for, "viewer", "Viewer@123"))
    assert client.get("/api/behavior-profiles", headers=viewer).status_code == 403
