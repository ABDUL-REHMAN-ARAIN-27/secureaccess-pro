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


def test_protected_route_requires_token(client):
    assert client.get("/api/protected/hr").status_code == 401


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
