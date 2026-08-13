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
from mailer import send_otp_email
from models import User, LoginHistory, ROLE_VIEWER
from ratelimit import rate_limited
from security import client_ip, record_access

auth_bp = Blueprint("auth", __name__)


def password_policy_error(password, min_length):
    """Return a message if the password fails the policy, else None (NIST-style:
    length + character variety)."""
    if len(password) < min_length:
        return f"Password must be at least {min_length} characters"
    if not any(c.islower() for c in password):
        return "Password must include a lowercase letter"
    if not any(c.isupper() for c in password):
        return "Password must include an uppercase letter"
    if not any(c.isdigit() for c in password):
        return "Password must include a digit"
    if not any(not c.isalnum() for c in password):
        return "Password must include a special character"
    return None


@auth_bp.route("/api/request-otp", methods=["POST"])
@rate_limited("otp")
def request_otp():
    """Verify the password, then email a one-time code to the user's registered
    address. The JWT is only issued later once this code is submitted to /login.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = User.query.filter_by(username=username).first()
    # Do not reveal whether the account exists / password is right.
    if not user or user.is_locked() or not user.check_password(password):
        return jsonify({"message": "If the credentials are valid, a code has been sent."}), 200

    cfg = current_app.config
    code = User.generate_otp(cfg["OTP_LENGTH"])
    user.set_email_otp(code, cfg["OTP_EXPIRES_MINUTES"])
    db.session.commit()

    delivered, dev_code = send_otp_email(user.email, code)
    record_access(username, "OTP_REQUEST", user.email or "", "SENT")

    resp = {
        "message": f"A login code was sent to {_mask_email(user.email)}.",
        "delivered": delivered,
        "expires_minutes": cfg["OTP_EXPIRES_MINUTES"],
    }
    # Dev mode only (no SMTP configured): surface the code so it stays demoable.
    if dev_code is not None:
        resp["dev_code"] = dev_code
        resp["message"] += " (DEV MODE: email not configured — code shown for testing)"
    return jsonify(resp), 200


def _mask_email(email):
    if not email or "@" not in email:
        return "your email"
    name, domain = email.split("@", 1)
    head = name[:2] if len(name) > 2 else name[:1]
    return f"{head}***@{domain}"


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
@rate_limited("login")
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

    # Factor 2: the emailed OTP, or an authenticator-app TOTP (either is accepted
    # so the system works whether or not SMTP is configured).
    ok_email = user.verify_email_otp(totp_code)
    ok_totp = user.verify_totp(
        totp_code,
        interval=cfg["TOTP_INTERVAL"],
        valid_window=cfg["TOTP_VALID_WINDOW"],
    )
    if not (ok_email or ok_totp):
        user.register_failure(cfg["MAX_FAILED_ATTEMPTS"], cfg["LOCKOUT_MINUTES"])
        db.session.commit()
        _log_login(username, "FAILED", "Invalid 2FA code")
        record_access(username, "LOGIN", "SYSTEM", "FAILED")
        return jsonify({"error": "Invalid 2FA code"}), 401

    # Success — clear the one-time email code, reset failures, issue the token.
    user.clear_email_otp()
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
    policy_error = password_policy_error(password, current_app.config["PASSWORD_MIN_LENGTH"])
    if policy_error:
        return jsonify({"error": policy_error}), 400
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
