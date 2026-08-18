"""
Pytest fixtures: an isolated in-memory app + the three demo users.

Each test run gets a fresh SQLite in-memory database so tests never touch the
real secureaccess_pro.db, and TOTP codes are computed live from each user's
secret via pyotp.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from extensions import db  # noqa: E402
from models import User, Patient, ROLE_ADMIN, ROLE_USER, ROLE_VIEWER  # noqa: E402
from patient_seed import generate_patients  # noqa: E402


import tempfile

_TMP_FILES = tempfile.mkdtemp(prefix="sap-test-")


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    JWT_SECRET_KEY = "test-secret"
    MAX_FAILED_ATTEMPTS = 3
    LOCKOUT_MINUTES = 15
    # Isolate uploaded/quarantined files to a throwaway temp dir.
    FILE_STORE_DIR = os.path.join(_TMP_FILES, "store")
    FILE_QUARANTINE_DIR = os.path.join(_TMP_FILES, "quarantine")
    FILE_TMP_DIR = os.path.join(_TMP_FILES, "tmp")
    AUDIT_ANCHOR_FILE = os.path.join(_TMP_FILES, "anchor.log")


DEMO = [
    ("admin", "Admin@123", ROLE_ADMIN),
    ("user", "User@123", ROLE_USER),
    ("viewer", "Viewer@123", ROLE_VIEWER),
]


@pytest.fixture()
def app():
    # Each test starts with a clean external audit anchor file.
    try:
        open(TestConfig.AUDIT_ANCHOR_FILE, "w").close()
    except OSError:
        os.makedirs(_TMP_FILES, exist_ok=True)
        open(TestConfig.AUDIT_ANCHOR_FILE, "w").close()
    app = create_app(TestConfig)
    with app.app_context():
        db.drop_all()
        db.create_all()
        for username, password, role in DEMO:
            u = User(username=username, email=f"{username}@x.com", role=role,
                     totp_secret=User.new_totp_secret())
            u.set_password(password)
            db.session.add(u)
        for p in generate_patients():
            db.session.add(Patient(**p))
        db.session.commit()
    yield app


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear the in-memory rate limiter between tests so counts don't leak."""
    import ratelimit
    ratelimit.reset()
    yield
    ratelimit.reset()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def totp_for(app):
    """Return a helper that yields the current TOTP code for a username."""
    def _code(username):
        with app.app_context():
            return User.query.filter_by(username=username).first().current_totp()
    return _code


def login(client, username, password, code):
    return client.post(
        "/api/login",
        json={"username": username, "password": password, "tfa_code": code},
    )


def token_for(client, totp_for, username, password):
    resp = login(client, username, password, totp_for(username))
    return resp.get_json()["token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}
