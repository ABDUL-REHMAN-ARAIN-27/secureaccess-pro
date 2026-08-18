"""
Backup / recovery code generation and verification.

Codes are single-use and stored only as bcrypt hashes. `generate` returns the
plaintext codes once (to display to the user); `verify_and_consume` accepts a
code as the second factor and marks it used so it cannot be replayed.
"""

import secrets
from datetime import datetime

import bcrypt

from extensions import db
from models import BackupCode

_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no ambiguous chars


def _new_code():
    part = lambda: "".join(secrets.choice(_ALPHABET) for _ in range(4))
    return f"{part()}-{part()}"


def generate(username, n=10):
    """Replace any existing codes with n fresh ones. Returns the plaintext list."""
    BackupCode.query.filter_by(username=username).delete(synchronize_session=False)
    codes = []
    for _ in range(n):
        code = _new_code()
        codes.append(code)
        db.session.add(BackupCode(
            username=username,
            code_hash=bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode(),
        ))
    db.session.commit()
    return codes


def verify_and_consume(username, code):
    """If `code` matches an unused backup code for the user, consume it and
    return True; otherwise return False. Never raises."""
    code = (code or "").strip().upper()
    if not code:
        return False
    try:
        for row in BackupCode.query.filter_by(username=username, used=False).all():
            if bcrypt.checkpw(code.encode(), row.code_hash.encode()):
                row.used = True
                row.used_at = datetime.utcnow()
                db.session.commit()
                return True
    except Exception:
        db.session.rollback()
    return False


def remaining(username):
    return BackupCode.query.filter_by(username=username, used=False).count()
