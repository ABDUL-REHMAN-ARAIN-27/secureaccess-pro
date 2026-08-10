"""
Shared security helpers: audit logging + role-based access control.
"""

from functools import wraps

from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity

from extensions import db
from models import AccessLog


def client_ip():
    """Best-effort client IP, honouring a reverse proxy if present."""
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr


def record_access(username, action, resource, status):
    """Write an entry to the access/audit log stream."""
    try:
        db.session.add(
            AccessLog(
                username=username,
                action=action,
                resource=resource,
                status=status,
                ip_address=client_ip(),
            )
        )
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
