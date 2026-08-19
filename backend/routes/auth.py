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
from flask_jwt_extended import (
    create_access_token,
    decode_token,
    jwt_required,
    get_jwt_identity,
    set_access_cookies,
)

from extensions import db
from mailer import send_otp_email, send_reset_email, send_welcome_email
from models import User, LoginHistory, ROLE_USER, ROLE_VIEWER
from ratelimit import rate_limited
from security import client_ip, record_access, resolve_ip
import risk as risk_engine

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
                ip_address=resolve_ip(username),
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

    # Blocked by an administrator.
    if user.is_blocked:
        _log_login(username, "FAILED", "Access blocked by administrator")
        record_access(username, "LOGIN", "SYSTEM", "BLOCKED")
        return jsonify({"error": "Your access has been blocked by the administrator."}), 403

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
    # A single-use backup/recovery code is accepted as the second factor, but is
    # only consumed if the primary factors did not already match.
    ok_backup = False
    if not (ok_email or ok_totp):
        import backupcodes
        ok_backup = backupcodes.verify_and_consume(username, totp_code)
    if not (ok_email or ok_totp or ok_backup):
        user.register_failure(cfg["MAX_FAILED_ATTEMPTS"], cfg["LOCKOUT_MINUTES"])
        db.session.commit()
        _log_login(username, "FAILED", "Invalid 2FA code")
        record_access(username, "LOGIN", "SYSTEM", "FAILED")
        return jsonify({"error": "Invalid 2FA code"}), 401

    # Success — clear the one-time email code, reset failures, issue the token.
    user.clear_email_otp()
    user.reset_failures()
    db.session.commit()

    # --- Phase 2: Device Trust + Risk-Based Access Control -----------------
    ip = resolve_ip(username)
    device_id = risk_engine.read_device_id()
    device_fp = risk_engine.device_fingerprint(username, device_id)
    score, level, factors, known_device = risk_engine.score_login(user, ip, device_fp)
    decision = risk_engine.decide("LOGIN", level)  # LOGIN always ALLOW (MFA passed)

    # Passing full MFA trusts this device going forward.
    risk_engine.register_device(username, device_fp, ip, trust=True)
    db.session.commit()

    access_token = create_access_token(
        identity=user.username,
        additional_claims={"role": user.role, "email": user.email},
    )

    # Record the session so it can be revoked later (continuous verification).
    jti = decode_token(access_token)["jti"]
    expires_at = datetime.utcnow() + cfg["JWT_ACCESS_TOKEN_EXPIRES"]
    risk_engine.create_session(jti, user, device_fp, ip, score, level, expires_at)
    risk_engine.log_risk_event(username, "LOGIN", "Authentication", ip, device_fp,
                               score, level, decision, factors)

    # UEBA learns this successful login into the user's behaviour baseline.
    try:
        import ueba
        ueba.observe_login(username, ip, device_fp, level)  # anti-poisoning: skips flagged logins
    except Exception:
        pass

    _log_login(username, "SUCCESS")
    record_access(username, "LOGIN", "SYSTEM", "SUCCESS")

    body = {
        "username": user.username,
        "role": user.role,
        "expires_in_minutes": int(
            cfg["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds() // 60
        ),
        "risk": {
            "score": score,
            "cvss": risk_engine.cvss_of(score),
            "level": level,
            "factors": factors,
            "known_device": known_device,
        },
    }
    # The browser SPA sends X-Client-Type: browser and therefore receives NO
    # token in the body — the JWT reaches the browser only inside the HttpOnly
    # cookie set below, so it is invisible to page JavaScript (nothing to steal
    # via XSS) and never appears in the login response / Network tab. Every
    # other (native/header) client — the desktop app, the API/CLI, the
    # test-suite — gets the raw token here to carry in an Authorization header.
    if request.headers.get("X-Client-Type", "").strip().lower() != "browser":
        body["token"] = access_token

    resp = jsonify(body)
    # Browser storage: write the JWT into an HttpOnly, Secure, SameSite=Strict
    # cookie (+ a readable CSRF token cookie) so JavaScript cannot exfiltrate
    # the session token via XSS.
    set_access_cookies(resp, access_token)
    return resp, 200


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

    # Self-registration may choose User or Viewer (never Admin).
    chosen_role = (data.get("role") or ROLE_VIEWER).strip().capitalize()
    if chosen_role not in (ROLE_USER, ROLE_VIEWER):
        chosen_role = ROLE_VIEWER

    user = User(username=username, email=email, role=chosen_role,
                totp_secret=User.new_totp_secret())
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": f"Registration failed: {exc}"}), 500

    record_access(username, "REGISTER", "SYSTEM", "SUCCESS")

    # Issue single-use MFA backup codes (shown once for the user to store).
    import backupcodes
    codes = backupcodes.generate(username, n=10)

    # Professional welcome email to the new account's registered address.
    try:
        send_welcome_email(email, username, chosen_role)
    except Exception:
        pass

    return (
        jsonify(
            {
                "message": "Registration successful — a welcome email has been sent. "
                "You can now log in.",
                "username": username,
                "role": chosen_role,
                "totp_secret": user.totp_secret,
                "provisioning_uri": user.provisioning_uri(
                    issuer=current_app.config["TOTP_ISSUER"],
                    interval=current_app.config["TOTP_INTERVAL"],
                ),
                "backup_codes": codes,
            }
        ),
        201,
    )


@auth_bp.route("/api/forgot-password", methods=["POST"])
@rate_limited("otp")
def forgot_password():
    """Email a password-reset code to the account's registered address."""
    data = request.get_json(silent=True) or {}
    ident = (data.get("username") or data.get("email") or "").strip()
    user = User.query.filter(
        (User.username == ident) | (User.email == ident)
    ).first()

    resp = {"message": "If the account exists, a reset code has been sent to its email."}
    if user and not user.is_blocked:
        code = User.generate_otp(current_app.config["OTP_LENGTH"])
        user.set_reset_code(code, current_app.config["RESET_EXPIRES_MINUTES"])
        db.session.commit()
        _delivered, dev_code = send_reset_email(user.email, code)
        record_access(user.username, "PASSWORD_RESET_REQUEST", user.email or "", "SENT")
        if dev_code is not None:
            resp["dev_code"] = dev_code
            resp["message"] += " (DEV MODE: code shown for testing)"
    return jsonify(resp), 200


@auth_bp.route("/api/reset-password", methods=["POST"])
@rate_limited("otp")
def reset_password():
    """Verify the emailed reset code and set a new password."""
    data = request.get_json(silent=True) or {}
    ident = (data.get("username") or data.get("email") or "").strip()
    code = data.get("code") or ""
    new_password = data.get("password") or ""
    confirm = data.get("confirm_password", new_password)

    user = User.query.filter(
        (User.username == ident) | (User.email == ident)
    ).first()
    if not user or not user.verify_reset_code(code):
        return jsonify({"error": "Invalid or expired reset code"}), 400
    if new_password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    policy_error = password_policy_error(new_password, current_app.config["PASSWORD_MIN_LENGTH"])
    if policy_error:
        return jsonify({"error": policy_error}), 400

    user.set_password(new_password)
    user.clear_reset_code()
    user.reset_failures()
    # Security: a password reset revokes every existing session for this account,
    # so an attacker holding an old token is forced out immediately.
    from models import SessionToken
    SessionToken.query.filter_by(username=user.username, revoked=False).update(
        {"revoked": True, "revoked_reason": "password reset"}, synchronize_session=False)
    db.session.commit()
    record_access(user.username, "PASSWORD_RESET", "SYSTEM", "SUCCESS")
    return jsonify({"message": "Password reset successful. You can now log in."}), 200


@auth_bp.route("/api/backup-codes/remaining", methods=["GET"])
@jwt_required()
def backup_codes_remaining():
    import backupcodes
    return jsonify({"remaining": backupcodes.remaining(get_jwt_identity())})


@auth_bp.route("/api/backup-codes/regenerate", methods=["POST"])
@jwt_required()
def backup_codes_regenerate():
    """Issue a fresh set of single-use backup codes (invalidates the old set)."""
    import backupcodes
    username = get_jwt_identity()
    codes = backupcodes.generate(username, n=10)
    record_access(username, "BACKUP_CODES_REGENERATED", "SYSTEM", "SUCCESS")
    return jsonify({"message": "New backup codes generated. Save them now.",
                    "backup_codes": codes})
