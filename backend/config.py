"""
SecureAccess Pro - Configuration
================================

Central configuration for the Zero Trust backend. Values are read from
environment variables (see .env.example) with safe development defaults so the
system runs out-of-the-box on SQLite while still supporting PostgreSQL in
production.
"""

import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _default_database_uri():
    """Use PostgreSQL when DATABASE_URL is provided, otherwise fall back to a
    local SQLite file so the project is demoable without a DB server."""
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    return "sqlite:///" + os.path.join(BASE_DIR, "secureaccess_pro.db")


class Config:
    # --- Database ---
    SQLALCHEMY_DATABASE_URI = _default_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- JWT / Zero Trust session policy ---
    # Presentation spec: JWT tokens expire within a configurable 15-minute window.
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-secret-change-in-production")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.environ.get("JWT_EXPIRES_MINUTES", "15"))
    )

    # --- Multi-Factor Authentication (TOTP) ---
    # 30-second time step is the standard TOTP window referenced in the threat model.
    TOTP_ISSUER = os.environ.get("TOTP_ISSUER", "SecureAccess Pro")
    TOTP_INTERVAL = int(os.environ.get("TOTP_INTERVAL", "30"))
    TOTP_VALID_WINDOW = int(os.environ.get("TOTP_VALID_WINDOW", "1"))

    # --- Email OTP (second factor delivered to the user's registered email) ---
    OTP_LENGTH = int(os.environ.get("OTP_LENGTH", "6"))
    OTP_EXPIRES_MINUTES = int(os.environ.get("OTP_EXPIRES_MINUTES", "5"))
    # SMTP settings (Gmail: host smtp.gmail.com, port 587, an App Password).
    # Leave SMTP_USER/SMTP_PASSWORD empty to run in dev mode: the code is
    # printed to the server console instead of being emailed.
    SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "no-reply@secureaccess.pro"))

    # --- Brute-force protection ---
    # Threat model: account lockout after 3 consecutive failed attempts.
    MAX_FAILED_ATTEMPTS = int(os.environ.get("MAX_FAILED_ATTEMPTS", "3"))
    LOCKOUT_MINUTES = int(os.environ.get("LOCKOUT_MINUTES", "15"))

    # --- Server ---
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "5000"))
    DEBUG = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
