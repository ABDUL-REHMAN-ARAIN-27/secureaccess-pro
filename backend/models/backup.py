"""
MFA backup / recovery codes.

Single-use codes issued at enrolment so a user who loses their authenticator (or
cannot receive the email OTP) can still complete the second factor. Only a bcrypt
hash of each code is stored; the plaintext is shown to the user exactly once.
"""

from datetime import datetime

from extensions import db


class BackupCode(db.Model):
    __tablename__ = "backup_codes"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
