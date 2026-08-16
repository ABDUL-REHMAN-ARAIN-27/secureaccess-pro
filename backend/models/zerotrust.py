"""
Phase 2 — Zero Trust risk-engine models.

Three tables extend the original schema without touching it:

    TrustedDevice : per-user device fingerprints (device-trust).
    SessionToken  : one row per issued JWT, so a stateless token can be
                    *revoked* on demand (continuous verification).
    RiskEvent     : an audit trail of every risk score + policy decision, which
                    powers the admin "Risk & Policy" dashboard tab.
"""

from datetime import datetime

from extensions import db


class TrustedDevice(db.Model):
    """A device (browser/machine) the system has seen for a given user.

    The fingerprint is a salted hash of a random id the client stores locally —
    never anything personally identifying. `trusted` is False the first time a
    device appears (elevated risk / step-up) and flips True once the user has
    completed full MFA from it; an admin can revoke trust to force step-up again.
    """

    __tablename__ = "trusted_devices"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, nullable=False)
    device_fp = db.Column(db.String(64), index=True, nullable=False)
    label = db.Column(db.String(120))          # e.g. "Chrome on Windows"
    trusted = db.Column(db.Boolean, default=False, nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_ip = db.Column(db.String(64))

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "device_fp": (self.device_fp or "")[:12],
            "label": self.label,
            "trusted": bool(self.trusted),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "last_ip": self.last_ip,
        }


class SessionToken(db.Model):
    """One record per issued access token (keyed by the JWT `jti`).

    Because the JWT itself is stateless, this table is what lets us *revoke* a
    live session: the JWT blocklist loader checks `revoked` for the jti on every
    request, so continuous verification can kill a session mid-flight.
    """

    __tablename__ = "session_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(64), unique=True, index=True, nullable=False)
    username = db.Column(db.String(50), index=True, nullable=False)
    role = db.Column(db.String(20))
    device_fp = db.Column(db.String(64))
    ip_address = db.Column(db.String(64))
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(10), default="LOW")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    revoked_reason = db.Column(db.String(160))

    def is_active(self):
        if self.revoked:
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        return True

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "device_fp": (self.device_fp or "")[:12],
            "ip_address": self.ip_address,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "active": self.is_active(),
            "revoked": bool(self.revoked),
            "revoked_reason": self.revoked_reason,
        }


class RiskEvent(db.Model):
    """A scored decision made by the risk/policy engine (login or access-time)."""

    __tablename__ = "risk_events"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True)
    phase = db.Column(db.String(20))           # LOGIN / ACCESS
    resource = db.Column(db.String(100))
    ip_address = db.Column(db.String(64))
    device_fp = db.Column(db.String(64))
    score = db.Column(db.Integer, default=0)
    level = db.Column(db.String(10))           # LOW / MEDIUM / HIGH
    decision = db.Column(db.String(20))        # ALLOW / STEP_UP / REVOKE / BLOCK
    factors = db.Column(db.String(400))        # human-readable "reasons"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "phase": self.phase,
            "resource": self.resource,
            "ip_address": self.ip_address,
            "device_fp": (self.device_fp or "")[:12],
            "score": self.score,
            "level": self.level,
            "decision": self.decision,
            "factors": self.factors,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
