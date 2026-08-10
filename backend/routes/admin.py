"""
Admin / monitoring blueprint (Admin role only).

Powers the real-time security dashboard: access logs, login history, raw site
access, aggregate metrics, and user/role management.
"""

import csv
import io
from datetime import datetime, timedelta

from flask import Blueprint, Response, jsonify, request
from flask_jwt_extended import get_jwt_identity

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
