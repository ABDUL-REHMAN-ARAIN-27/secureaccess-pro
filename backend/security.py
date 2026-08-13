"""
Shared security helpers: audit logging + role-based access control.
"""

from datetime import datetime
from functools import wraps

from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity

from audit import compute_entry_hash
from extensions import db
from models import AccessLog


def client_ip():
    """Best-effort client IP, honouring a reverse proxy if present."""
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr


def record_access(username, action, resource, status):
    """Write a hash-chained (tamper-evident) entry to the audit log stream."""
    try:
        ip = client_ip()
        ts = datetime.utcnow()
        last = AccessLog.query.order_by(AccessLog.id.desc()).first()
        prev = last.entry_hash if last and last.entry_hash else "GENESIS"
        entry = AccessLog(
            username=username,
            action=action,
            resource=resource,
            status=status,
            ip_address=ip,
            timestamp=ts,
            prev_hash=prev,
        )
        entry.entry_hash = compute_entry_hash(
            prev, username, action, resource, status, ip, ts.isoformat()
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:  # pragma: no cover - logging must never break a request
        db.session.rollback()


def roles_required(*allowed_roles):
    """
    Server-side RBAC guard. Verifies the JWT, checks the role claim against the
    allowed set, and logs a DENIED access-control event on rejection so that
    privilege-escalation / unauthorized-access attempts surface on the dashboard.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            role = get_jwt().get("role", "")
            username = get_jwt_identity()
            if role not in allowed_roles:
                record_access(
                    username, "ACCESS", request.path, "DENIED"
                )
                return (
                    jsonify(
                        {
                            "error": "Access denied",
                            "detail": "Your role does not permit this resource.",
                            "role": role,
                        }
                    ),
                    403,
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator
