"""
Authentication blueprint.

Implements the Zero Trust login flow described in the seminar:
    1. Verify username + bcrypt password.
    2. Require a valid TOTP second factor (JWT is issued only after both pass).
    3. Enforce account lockout after N consecutive failed attempts.
    4. Issue a short-lived (15 min) JWT carrying the role claim.

Every attempt is written to login_history + access_logs for the dashboard.
"""

from datetime import datetime

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import create_access_token

from extensions import db
from models import User, LoginHistory, ROLE_VIEWER
from security import client_ip, record_access

auth_bp = Blueprint("auth", __name__)


def _log_login(username, status, reason=None):
    try:
        db.session.add(
            LoginHistory(
                username=username,
                ip_address=client_ip(),
                status=status,
                failure_reason=reason,
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()


@auth_bp.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    totp_code = data.get("tfa_code") or data.get("totp") or ""

    cfg = current_app.config
    user = User.query.filter_by(username=username).first()

    # Unknown user — do not reveal which factor failed.
    if not user:
        _log_login(username, "FAILED", "Invalid username or password")
        record_access(username, "LOGIN", "SYSTEM", "FAILED")
        return jsonify({"error": "Invalid credentials"}), 401

    # Locked account (brute-force protection).
    if user.is_locked():
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() // 60) + 1
        _log_login(username, "FAILED", "Account locked")
        record_access(username, "LOGIN", "SYSTEM", "LOCKED")
        return (
            jsonify(
                {
                    "error": "Account locked due to repeated failed attempts.",
                    "retry_after_minutes": remaining,
                }
            ),
            423,
        )

    # Factor 1: password.
    if not user.check_password(password):
        user.register_failure(cfg["MAX_FAILED_ATTEMPTS"], cfg["LOCKOUT_MINUTES"])
        db.session.commit()
        _log_login(username, "FAILED", "Invalid username or password")
        record_access(username, "LOGIN", "SYSTEM", "FAILED")
        return jsonify({"error": "Invalid credentials"}), 401

    # Factor 2: TOTP.
    if not user.verify_totp(
        totp_code,
        interval=cfg["TOTP_INTERVAL"],
        valid_window=cfg["TOTP_VALID_WINDOW"],
    ):
        user.register_failure(cfg["MAX_FAILED_ATTEMPTS"], cfg["LOCKOUT_MINUTES"])
        db.session.commit()
        _log_login(username, "FAILED", "Invalid 2FA code")
        record_access(username, "LOGIN", "SYSTEM", "FAILED")
        return jsonify({"error": "Invalid 2FA code"}), 401

    # Success — reset failure counter and issue a short-lived token.
    user.reset_failures()
    db.session.commit()

    access_token = create_access_token(
        identity=user.username,
        additional_claims={"role": user.role, "email": user.email},
    )

    _log_login(username, "SUCCESS")
    record_access(username, "LOGIN", "SYSTEM", "SUCCESS")

    return (
        jsonify(
            {
                "token": access_token,
                "username": user.username,
                "role": user.role,
                "expires_in_minutes": int(
                    cfg["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds() // 60
                ),
            }
        ),
        200,
    )


@auth_bp.route("/api/register", methods=["POST"])
def register():
    """Self-service registration. New accounts default to the Viewer role and
    receive a freshly generated TOTP secret returned once for enrolment."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm_password", password)

    if not username or not password or not email:
        return jsonify({"error": "Username, email and password are required"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if "@" not in email or "." not in email:
        return jsonify({"error": "Please enter a valid email address"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    user = User(username=username, email=email, role=ROLE_VIEWER,
                totp_secret=User.new_totp_secret())
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": f"Registration failed: {exc}"}), 500

    record_access(username, "REGISTER", "SYSTEM", "SUCCESS")

    return (
        jsonify(
            {
                "message": "Registration successful. Enrol the secret below in your "
                "authenticator app, then log in.",
                "username": username,
                "role": ROLE_VIEWER,
                "totp_secret": user.totp_secret,
                "provisioning_uri": user.provisioning_uri(
                    issuer=current_app.config["TOTP_ISSUER"],
                    interval=current_app.config["TOTP_INTERVAL"],
                ),
            }
        ),
        201,
    )
