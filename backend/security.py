"""
Shared security helpers: audit logging + role-based access control.
"""

import hashlib
from datetime import datetime
from functools import wraps

from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity

from audit import compute_entry_hash
from extensions import db
from models import AccessLog, User


def client_ip():
    """Best-effort client IP, honouring a reverse proxy if present."""
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr


def _is_local(ip):
    return not ip or ip == "::1" or ip.startswith(("127.", "10.", "192.168.", "172."))


def _sim_ip(username):
    """A stable, realistic-looking public IP derived from the username. Used so
    each user shows a distinct source address on the dashboard when everyone is
    actually connecting from localhost (demo)."""
    h = hashlib.md5((username or "anon").encode("utf-8")).hexdigest()
    a = 100 + int(h[0:2], 16) % 124
    b = int(h[2:4], 16) % 256
    c = int(h[4:6], 16) % 256
    d = 1 + int(h[6:8], 16) % 254
    return f"{a}.{b}.{c}.{d}"


def resolve_ip(username=None):
    """Real client IP in production; a per-user simulated IP for local demos."""
    real = client_ip()
    if not _is_local(real):
        return real
    return _sim_ip(username) if username else real


def record_access(username, action, resource, status):
    """Write a hash-chained (tamper-evident) entry to the audit log stream."""
    try:
        ip = resolve_ip(username)
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


def continuous_verify(resource):
    """
    Phase 2 — Continuous Verification.

    Wraps a *sensitive* resource so that access is re-evaluated on every single
    request, not just at login. The live risk score (account state, device / IP
    drift, resource sensitivity) is fed to the policy engine:

        LOW     -> allow
        MEDIUM  -> step-up: demand fresh MFA before serving the resource (401)
        HIGH    -> revoke the session immediately + alert the admin (403)

    This is what closes the classic stateless-JWT gap: a token that was valid a
    minute ago is worthless the instant the account is blocked or the session is
    judged high-risk. Apply *below* @roles_required so the role check runs first.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Imported lazily to avoid a circular import at module load.
            import risk as risk_engine

            username = get_jwt_identity()
            jti = get_jwt().get("jti")
            user = User.query.filter_by(username=username).first()
            session = risk_engine.session_for_jti(jti)

            if session is not None:
                session.last_seen = datetime.utcnow()
                db.session.commit()

            if user is None:
                return jsonify({"error": "Unknown session"}), 401

            score, level, factors = risk_engine.score_access(user, resource, session)
            decision = risk_engine.decide("ACCESS", level)
            ip = resolve_ip(username)
            device_fp = session.device_fp if session else ""

            risk_engine.log_risk_event(
                username, "ACCESS", resource, ip, device_fp,
                score, level, decision, factors,
            )

            if decision == "REVOKE":
                if session is not None:
                    risk_engine.revoke_session(session, f"High-risk access to {resource}")
                record_access(username, "CONTINUOUS_VERIFY", resource, "DENIED")
                return (
                    jsonify({
                        "error": "Session revoked by continuous verification.",
                        "detail": "This access was scored HIGH risk. Please re-authenticate.",
                        "risk_score": score,
                        "risk_level": level,
                        "factors": factors,
                        "session_revoked": True,
                    }),
                    403,
                )

            if decision == "STEP_UP":
                record_access(username, "CONTINUOUS_VERIFY", resource, "STEP_UP")
                return (
                    jsonify({
                        "error": "Additional verification required.",
                        "detail": "This access was scored MEDIUM risk. Re-verify with MFA.",
                        "risk_score": score,
                        "risk_level": level,
                        "factors": factors,
                        "step_up_required": True,
                    }),
                    401,
                )

            return fn(*args, **kwargs)

        return wrapper

    return decorator
