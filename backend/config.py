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

# Load backend/.env (if present) so SMTP credentials etc. are picked up.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"))
except ImportError:  # python-dotenv is optional
    pass


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
    RESET_EXPIRES_MINUTES = int(os.environ.get("RESET_EXPIRES_MINUTES", "15"))
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

    # --- Password policy (enforced on self-registration) ---
    PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", "8"))

    # --- API rate limiting (anti-automation / anti-DoS) ---
    RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "30"))
    RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))

    # --- Anomaly detection thresholds (Security Alerts) ---
    # Failed logins from ONE source IP spread across >=2 accounts within the
    # 15-minute window that raise a credential-stuffing alert.
    IP_BRUTEFORCE_THRESHOLD = int(os.environ.get("IP_BRUTEFORCE_THRESHOLD", "5"))

    # --- Phase 2: Risk-Based Access Control (risk engine weights) ---
    # A login/access request is scored 0-100 from these signals; the total maps
    # to a LOW / MEDIUM / HIGH band that the policy engine turns into a decision.
    RISK_WEIGHT_FAILED = int(os.environ.get("RISK_WEIGHT_FAILED", "12"))       # per recent failed attempt
    RISK_WEIGHT_NEW_DEVICE = int(os.environ.get("RISK_WEIGHT_NEW_DEVICE", "30"))  # unrecognised device
    RISK_WEIGHT_NEW_IP = int(os.environ.get("RISK_WEIGHT_NEW_IP", "20"))       # never-seen source IP
    RISK_WEIGHT_OFFHOURS = int(os.environ.get("RISK_WEIGHT_OFFHOURS", "10"))   # outside 06:00-22:00
    RISK_WEIGHT_BLOCKED = int(os.environ.get("RISK_WEIGHT_BLOCKED", "100"))    # admin-blocked account
    RISK_WEIGHT_LOCKED = int(os.environ.get("RISK_WEIGHT_LOCKED", "60"))       # locked-out account
    RISK_WEIGHT_DEVICE_MISMATCH = int(os.environ.get("RISK_WEIGHT_DEVICE_MISMATCH", "55"))  # session hijack signal
    RISK_WEIGHT_IP_MISMATCH = int(os.environ.get("RISK_WEIGHT_IP_MISMATCH", "20"))          # IP changed mid-session

    # Resource sensitivity added to the score during continuous verification.
    # Kept below the MEDIUM band so a normal, trusted session flows freely; only
    # a real anomaly (blocked/locked account, device/IP drift, untrusted device)
    # pushes a sensitive access into STEP_UP or REVOKE territory.
    RISK_SENSITIVITY = {
        "Finance Dashboard": 20,
        "Patient Records": 18,
        "HR Portal": 12,
        "Document Manager": 5,
    }
    RISK_WEIGHT_UNTRUSTED_AT_ACCESS = int(os.environ.get("RISK_WEIGHT_UNTRUSTED_AT_ACCESS", "30"))

    # Severity bands follow the CVSS v3 rating scale. The internal 0-100 score is
    # expressed as a CVSS 0.0-10.0 value (score / 10):
    #   None 0.0 | Low 0.1-3.9 | Medium 4.0-6.9 | High 7.0-8.9 | Critical 9.0-10.0
    # Thresholds below are the 0-100 lower bounds for MEDIUM / HIGH / CRITICAL.
    RISK_MEDIUM = int(os.environ.get("RISK_MEDIUM", "40"))     # CVSS 4.0
    RISK_HIGH = int(os.environ.get("RISK_HIGH", "70"))        # CVSS 7.0
    RISK_CRITICAL = int(os.environ.get("RISK_CRITICAL", "90"))  # CVSS 9.0

    # --- Secure File Upload + Malware Detection module ---
    # Files are never served from the web root; they live under backend/var/*.
    _VAR_DIR = os.path.join(BASE_DIR, "var")
    FILE_STORE_DIR = os.environ.get("FILE_STORE_DIR", os.path.join(_VAR_DIR, "store"))       # clean/approved
    FILE_QUARANTINE_DIR = os.environ.get("FILE_QUARANTINE_DIR", os.path.join(_VAR_DIR, "quarantine"))
    FILE_TMP_DIR = os.environ.get("FILE_TMP_DIR", os.path.join(_VAR_DIR, "tmp"))             # scan staging

    MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))
    MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

    # File-type policy. By default we accept EVERY format and rely on the scanner
    # + quarantine (Zero Trust: trust no file, scan it). Set UPLOAD_ALLOW_ALL_TYPES
    # =false to instead restrict uploads to the MIME allow-list below (content is
    # sniffed; the extension alone is never trusted).
    UPLOAD_ALLOW_ALL_TYPES = os.environ.get("UPLOAD_ALLOW_ALL_TYPES", "true").lower() == "true"
    UPLOAD_ALLOWED_MIME = [
        m.strip() for m in os.environ.get(
            "UPLOAD_ALLOWED_MIME",
            "application/pdf,text/plain,image/png,image/jpeg,image/gif,"
            "application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,"
            "application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,"
            "text/csv,application/zip"
        ).split(",") if m.strip()
    ]

    # Scanner engine: "demo" (EICAR + heuristics, no external deps) or "clamav"
    # (real signature engine via the clamd daemon). DEMO is clearly separated
    # from REAL detection and must never be presented as production AV coverage.
    SCANNER_MODE = os.environ.get("SCANNER_MODE", "demo").lower()
    CLAMAV_HOST = os.environ.get("CLAMAV_HOST", "127.0.0.1")
    CLAMAV_PORT = int(os.environ.get("CLAMAV_PORT", "3310"))
    CLAMAV_SOCKET = os.environ.get("CLAMAV_SOCKET", "")  # unix socket path (optional)
    SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "30"))

    # Policy: a malicious upload always quarantines + alerts. Auto-blocking the
    # user is OFF by default (opt-in) so the response stays configurable, not
    # aggressive — see requirement 12.
    MALWARE_AUTO_BLOCK = os.environ.get("MALWARE_AUTO_BLOCK", "false").lower() == "true"

    # --- UEBA: AI/behaviour-based adaptive risk ---
    # An unsupervised per-user behaviour model (User & Entity Behaviour Analytics)
    # that learns each account's normal login pattern and adds an *explainable*
    # anomaly contribution on top of the rule-based CVSS score. It stays quiet
    # until it has seen a few logins (cold-start), then flags personal deviations
    # (unusual hour, login bursts). Engine: "baseline" (numpy statistics, no deps)
    # or "iforest" (scikit-learn IsolationForest, used only if installed).
    UEBA_ENABLED = os.environ.get("UEBA_ENABLED", "true").lower() == "true"
    UEBA_MODEL = os.environ.get("UEBA_MODEL", "baseline").lower()
    UEBA_MIN_LOGINS = int(os.environ.get("UEBA_MIN_LOGINS", "4"))   # cold-start threshold
    UEBA_W_HOUR = int(os.environ.get("UEBA_W_HOUR", "22"))          # unusual-hour weight
    UEBA_W_BURST = int(os.environ.get("UEBA_W_BURST", "16"))        # login-burst weight
    UEBA_MAX = int(os.environ.get("UEBA_MAX", "35"))               # cap on UEBA contribution
    UEBA_BURST_SECONDS = int(os.environ.get("UEBA_BURST_SECONDS", "60"))

    # --- Server ---
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "5000"))
    DEBUG = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
