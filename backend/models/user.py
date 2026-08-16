"""
User model + role definitions.

Roles follow the RBAC Role-Permission Matrix from the project seminar:
    - Admin  : full access (dashboard, all apps, user/role management, logs)
    - User   : HR Portal + Document Manager
    - Viewer : Document Manager (read) only
"""

from datetime import datetime, timedelta

import bcrypt
import pyotp

from extensions import db

ROLE_ADMIN = "Admin"
ROLE_USER = "User"
ROLE_VIEWER = "Viewer"
ROLES = (ROLE_ADMIN, ROLE_USER, ROLE_VIEWER)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=ROLE_VIEWER)

    # TOTP shared secret (base32). Each user gets a unique secret at creation.
    totp_secret = db.Column(db.String(64), nullable=False)

    # Brute-force protection state.
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Admin can revoke a user's access (block) after suspicious activity.
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)

    # Email OTP (second factor delivered to the registered email).
    email_otp_hash = db.Column(db.String(255), nullable=True)
    email_otp_expires = db.Column(db.DateTime, nullable=True)

    # Password-reset code (emailed on 'forgot password').
    reset_hash = db.Column(db.String(255), nullable=True)
    reset_expires = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ------------------------------------------------------------------ #
    # Password helpers (bcrypt)
    # ------------------------------------------------------------------ #
    def set_password(self, raw_password: str) -> None:
        self.password_hash = bcrypt.hashpw(
            raw_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    def check_password(self, raw_password: str) -> bool:
        try:
            return bcrypt.checkpw(
                raw_password.encode("utf-8"), self.password_hash.encode("utf-8")
            )
        except (ValueError, AttributeError):
            return False

    # ------------------------------------------------------------------ #
    # TOTP helpers (pyotp)
    # ------------------------------------------------------------------ #
    @staticmethod
    def new_totp_secret() -> str:
        return pyotp.random_base32()

    def verify_totp(self, code: str, interval: int = 30, valid_window: int = 1) -> bool:
        if not code:
            return False
        totp = pyotp.TOTP(self.totp_secret, interval=interval)
        return totp.verify(str(code).strip(), valid_window=valid_window)

    def current_totp(self, interval: int = 30) -> str:
        """Return the code valid right now (used for the demo helper only)."""
        return pyotp.TOTP(self.totp_secret, interval=interval).now()

    def provisioning_uri(self, issuer: str = "SecureAccess Pro", interval: int = 30) -> str:
        """otpauth:// URI for authenticator apps (Google Authenticator, Authy)."""
        return pyotp.TOTP(self.totp_secret, interval=interval).provisioning_uri(
            name=self.username, issuer_name=issuer
        )

    # ------------------------------------------------------------------ #
    # Email OTP helpers (bcrypt-hashed, time-limited)
    # ------------------------------------------------------------------ #
    @staticmethod
    def generate_otp(length: int = 6) -> str:
        import secrets
        return "".join(secrets.choice("0123456789") for _ in range(length))

    def set_email_otp(self, code: str, expires_minutes: int = 5) -> None:
        self.email_otp_hash = bcrypt.hashpw(
            code.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        self.email_otp_expires = datetime.utcnow() + timedelta(minutes=expires_minutes)

    def verify_email_otp(self, code: str) -> bool:
        if not self.email_otp_hash or not self.email_otp_expires:
            return False
        if self.email_otp_expires < datetime.utcnow():
            return False
        try:
            return bcrypt.checkpw(
                str(code).strip().encode("utf-8"), self.email_otp_hash.encode("utf-8")
            )
        except (ValueError, AttributeError):
            return False

    def clear_email_otp(self) -> None:
        self.email_otp_hash = None
        self.email_otp_expires = None

    # ------------------------------------------------------------------ #
    # Password-reset code helpers
    # ------------------------------------------------------------------ #
    def set_reset_code(self, code: str, minutes: int = 15) -> None:
        self.reset_hash = bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        self.reset_expires = datetime.utcnow() + timedelta(minutes=minutes)

    def verify_reset_code(self, code: str) -> bool:
        if not self.reset_hash or not self.reset_expires:
            return False
        if self.reset_expires < datetime.utcnow():
            return False
        try:
            return bcrypt.checkpw(str(code).strip().encode("utf-8"), self.reset_hash.encode("utf-8"))
        except (ValueError, AttributeError):
            return False

    def clear_reset_code(self) -> None:
        self.reset_hash = None
        self.reset_expires = None

    # ------------------------------------------------------------------ #
    # Lockout helpers
    # ------------------------------------------------------------------ #
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > datetime.utcnow()

    def register_failure(self, max_attempts: int, lockout_minutes: int) -> None:
        self.failed_attempts = (self.failed_attempts or 0) + 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)

    def reset_failures(self) -> None:
        self.failed_attempts = 0
        self.locked_until = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "failed_attempts": self.failed_attempts,
            "locked": self.is_locked(),
            "blocked": bool(self.is_blocked),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
