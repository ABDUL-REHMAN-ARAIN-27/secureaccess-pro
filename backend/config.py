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

    # --- Brute-force protection ---
    # Threat model: account lockout after 3 consecutive failed attempts.
    MAX_FAILED_ATTEMPTS = int(os.environ.get("MAX_FAILED_ATTEMPTS", "3"))
    LOCKOUT_MINUTES = int(os.environ.get("LOCKOUT_MINUTES", "15"))

    # --- Server ---
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "5000"))
    DEBUG = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
