"""
Monitoring / audit models.

Three independent log streams power the real-time monitoring dashboard:
    - AccessLog     : application/resource access decisions (GRANTED / DENIED)
    - LoginHistory  : authentication attempts (SUCCESS / FAILED + reason)
    - SiteAccess    : raw HTTP request tracking (Zero Trust "verify everything")
"""

from datetime import datetime

from extensions import db


class AccessLog(db.Model):
    __tablename__ = "access_logs"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    action = db.Column(db.String(50))       # LOGIN / ACCESS / REGISTER ...
    resource = db.Column(db.String(100))    # HR Portal / Finance Dashboard ...
    status = db.Column(db.String(20))        # SUCCESS / GRANTED / DENIED / FAILED
    ip_address = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Tamper-evidence: each entry is chained to the previous one's hash, so any
    # later modification of an earlier row breaks the chain and is detectable.
    prev_hash = db.Column(db.String(64))
    entry_hash = db.Column(db.String(64))

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "action": self.action,
            "resource": self.resource,
            "status": self.status,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "entry_hash": self.entry_hash,
        }


class LoginHistory(db.Model):
    __tablename__ = "login_history"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(64))
    status = db.Column(db.String(20))         # SUCCESS / FAILED
    failure_reason = db.Column(db.String(120))

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "login_time": self.login_time.isoformat() if self.login_time else None,
            "ip_address": self.ip_address,
            "status": self.status,
            "failure_reason": self.failure_reason,
        }


class SiteAccess(db.Model):
    __tablename__ = "site_access"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64))
    method = db.Column(db.String(10))
    page_accessed = db.Column(db.String(200))
    access_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(300))
    status = db.Column(db.String(20))

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "method": self.method,
            "page_accessed": self.page_accessed,
            "access_time": self.access_time.isoformat() if self.access_time else None,
            "user_agent": self.user_agent,
            "status": self.status,
        }
