"""
Admin / monitoring blueprint (Admin role only).

Powers the real-time security dashboard: access logs, login history, raw site
access, aggregate metrics, and user/role management.
"""

import csv
import io
from collections import Counter
from datetime import datetime, timedelta

from flask import Blueprint, Response, current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity

from audit import verify_chain
from extensions import db
from models import (
    AccessLog,
    LoginHistory,
    SiteAccess,
    User,
    ROLE_ADMIN,
    ROLES,
)
from security import roles_required, record_access

admin_bp = Blueprint("admin", __name__)

_RESOURCE_NAMES = {
    "/api/protected/hr": "HR Portal",
    "/api/protected/finance": "Finance Dashboard",
    "/api/protected/patients": "Patient Records",
    "/api/protected/documents": "Document Manager",
    "/api/logs": "Access Logs (admin)",
    "/api/metrics": "Security Metrics (admin)",
    "/api/alerts": "Security Alerts (admin)",
    "/api/login-history": "Login History (admin)",
    "/api/site-access": "Site Access (admin)",
    "/api/users": "User Management (admin)",
    "/api/audit/verify": "Audit Log (admin)",
}


def _friendly_resource(resource):
    if not resource:
        return "a protected resource"
    return _RESOURCE_NAMES.get(resource, resource)


@admin_bp.route("/api/logs", methods=["GET"])
@roles_required(ROLE_ADMIN)
def get_logs():
    limit = request.args.get("limit", 100, type=int)
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(limit).all()
    return jsonify([log.to_dict() for log in logs])


@admin_bp.route("/api/login-history", methods=["GET"])
@roles_required(ROLE_ADMIN)
def get_login_history():
    limit = request.args.get("limit", 100, type=int)
    history = (
        LoginHistory.query.order_by(LoginHistory.login_time.desc()).limit(limit).all()
    )
    return jsonify([h.to_dict() for h in history])


@admin_bp.route("/api/site-access", methods=["GET"])
@roles_required(ROLE_ADMIN)
def get_site_access():
    limit = request.args.get("limit", 100, type=int)
    rows = SiteAccess.query.order_by(SiteAccess.access_time.desc()).limit(limit).all()
    return jsonify([r.to_dict() for r in rows])


@admin_bp.route("/api/audit/verify", methods=["GET"])
@roles_required(ROLE_ADMIN)
def verify_audit():
    """Recompute the audit hash-chain and report whether it is intact."""
    rows = AccessLog.query.order_by(AccessLog.id.asc()).all()
    return jsonify(verify_chain(rows))


@admin_bp.route("/api/alerts", methods=["GET"])
@roles_required(ROLE_ADMIN)
def get_alerts():
    """
    Lightweight anomaly detection over recent activity (SOC-style). Surfaces:
      - Brute-force: many failed logins for one user in a short window.
      - Privilege probing: many DENIED access attempts by one user.
      - Locked accounts.
    """
    window = datetime.utcnow() - timedelta(minutes=15)
    alerts = []

    # Brute-force: >= MAX_FAILED_ATTEMPTS failed logins per user in the window.
    threshold = current_app.config.get("MAX_FAILED_ATTEMPTS", 3)
    failed = (
        LoginHistory.query.filter(
            LoginHistory.status == "FAILED", LoginHistory.login_time >= window
        ).all()
    )
    per_user = Counter(f.username for f in failed)
    for username, count in per_user.items():
        if count >= threshold:
            alerts.append({
                "severity": "HIGH",
                "type": "Brute-force / credential attack",
                "subject": username or "unknown",
                "detail": f"{count} failed logins in the last 15 minutes",
            })

    # Access-rule violations: ANY denied attempt is flagged immediately, and
    # escalated to "privilege probing" once it repeats.
    denied = (
        AccessLog.query.filter(
            AccessLog.status == "DENIED", AccessLog.timestamp >= window
        ).order_by(AccessLog.timestamp.desc()).all()
    )
    denied_by_user = {}
    for d in denied:
        denied_by_user.setdefault(d.username, []).append(_friendly_resource(d.resource))
    for username, resources in denied_by_user.items():
        count = len(resources)
        tried = ", ".join(dict.fromkeys(resources[:4]))  # unique, keep order
        if count >= 3:
            alerts.append({
                "severity": "HIGH",
                "type": "Privilege escalation / probing",
                "subject": username or "unknown",
                "detail": f"{count} unauthorized attempts (rule violations) — tried: {tried}",
            })
        else:
            alerts.append({
                "severity": "MEDIUM",
                "type": "Access rule violation",
                "subject": username or "unknown",
                "detail": f"{count} unauthorized attempt(s) — tried: {tried}",
            })

    # Locked accounts.
    for u in User.query.filter(User.locked_until > datetime.utcnow()).all():
        alerts.append({
            "severity": "MEDIUM",
            "type": "Account locked",
            "subject": u.username,
            "detail": "Account locked after repeated failed logins",
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: order.get(a["severity"], 3))
    return jsonify({"count": len(alerts), "alerts": alerts,
                    "generated_at": datetime.utcnow().isoformat()})


@admin_bp.route("/api/metrics", methods=["GET"])
@roles_required(ROLE_ADMIN)
def get_metrics():
    """Aggregate counters for the dashboard KPI tiles."""
    since = datetime.utcnow() - timedelta(hours=24)

    total_logins = LoginHistory.query.count()
    failed_logins = LoginHistory.query.filter_by(status="FAILED").count()
    denied_access = AccessLog.query.filter_by(status="DENIED").count()
    granted_access = AccessLog.query.filter_by(status="GRANTED").count()
    locked_accounts = User.query.filter(User.locked_until > datetime.utcnow()).count()
    logins_24h = LoginHistory.query.filter(LoginHistory.login_time >= since).count()

    return jsonify(
        {
            "total_users": User.query.count(),
            "total_logins": total_logins,
            "failed_logins": failed_logins,
            "granted_access": granted_access,
            "denied_access": denied_access,
            "locked_accounts": locked_accounts,
            "logins_last_24h": logins_24h,
            "generated_at": datetime.utcnow().isoformat(),
        }
    )


# ---------------------------------------------------------------------------
# User / role management (Admin only)
# ---------------------------------------------------------------------------
@admin_bp.route("/api/users", methods=["GET"])
@roles_required(ROLE_ADMIN)
def list_users():
    users = User.query.order_by(User.id.asc()).all()
    return jsonify([u.to_dict() for u in users])


@admin_bp.route("/api/users/<int:user_id>/role", methods=["PUT"])
@roles_required(ROLE_ADMIN)
def update_role(user_id):
    data = request.get_json(silent=True) or {}
    new_role = (data.get("role") or "").strip()
    if new_role not in ROLES:
        return jsonify({"error": f"Role must be one of {list(ROLES)}"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.role = new_role
    db.session.commit()
    record_access(get_jwt_identity(), "MANAGE_ROLE",
                  f"user:{user.username}->{new_role}", "SUCCESS")
    return jsonify({"message": "Role updated", "user": user.to_dict()})


@admin_bp.route("/api/users/<int:user_id>/unlock", methods=["POST"])
@roles_required(ROLE_ADMIN)
def unlock_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.reset_failures()
    db.session.commit()
    record_access(get_jwt_identity(), "UNLOCK", f"user:{user.username}", "SUCCESS")
    return jsonify({"message": "Account unlocked", "user": user.to_dict()})


def _find_user(identifier):
    """Look up a user by numeric id or by username (from an alert subject)."""
    if str(identifier).isdigit():
        return User.query.get(int(identifier))
    return User.query.filter_by(username=identifier).first()


@admin_bp.route("/api/users/<identifier>/block", methods=["POST"])
@roles_required(ROLE_ADMIN)
def block_user(identifier):
    """Revoke a user's access after suspicious activity (admin action)."""
    user = _find_user(identifier)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.role == ROLE_ADMIN:
        return jsonify({"error": "Admin accounts cannot be blocked."}), 400
    user.is_blocked = True
    db.session.commit()
    record_access(get_jwt_identity(), "BLOCK", f"user:{user.username}", "SUCCESS")
    return jsonify({"message": f"{user.username} has been blocked", "user": user.to_dict()})


@admin_bp.route("/api/users/<identifier>/unblock", methods=["POST"])
@roles_required(ROLE_ADMIN)
def unblock_user(identifier):
    user = _find_user(identifier)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.is_blocked = False
    user.reset_failures()
    db.session.commit()
    record_access(get_jwt_identity(), "UNBLOCK", f"user:{user.username}", "SUCCESS")
    return jsonify({"message": f"{user.username} has been unblocked", "user": user.to_dict()})


# ---------------------------------------------------------------------------
# Audit export (Admin only) - "logs exportable for audit purposes"
# ---------------------------------------------------------------------------
_EXPORTS = {
    "access-logs": (
        lambda: AccessLog.query.order_by(AccessLog.timestamp.desc()).all(),
        ["timestamp", "username", "action", "resource", "status", "ip_address"],
    ),
    "login-history": (
        lambda: LoginHistory.query.order_by(LoginHistory.login_time.desc()).all(),
        ["login_time", "username", "status", "failure_reason", "ip_address"],
    ),
    "site-access": (
        lambda: SiteAccess.query.order_by(SiteAccess.access_time.desc()).all(),
        ["access_time", "method", "page_accessed", "ip_address", "status", "user_agent"],
    ),
}


@admin_bp.route("/api/export/<dataset>", methods=["GET"])
@roles_required(ROLE_ADMIN)
def export_csv(dataset):
    """Stream any audit dataset as a downloadable CSV file."""
    spec = _EXPORTS.get(dataset)
    if not spec:
        return jsonify({"error": f"Unknown dataset. Use one of {list(_EXPORTS)}"}), 404

    fetch, fields = spec
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in fetch():
        writer.writerow(row.to_dict())

    record_access(get_jwt_identity(), "EXPORT", dataset, "SUCCESS")
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={dataset}-{stamp}.csv"
        },
    )
