"""
Phase 2 — Zero Trust blueprint.

Admin-facing endpoints that power the "Risk & Policy" dashboard tab plus a
self-service logout that revokes the caller's own session:

    GET  /api/risk-events            recent risk scores + policy decisions
    GET  /api/risk-metrics           KPI counters for the tab
    GET  /api/sessions               issued sessions (active + revoked)
    POST /api/sessions/<id>/revoke   admin kills a live session
    GET  /api/devices                known devices (device-trust)
    POST /api/devices/<id>/trust     admin trusts a device
    POST /api/devices/<id>/untrust   admin revokes device trust (forces step-up)
    POST /api/logout                 caller revokes their own current session
"""

from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity

from extensions import db
from models import SessionToken, RiskEvent, TrustedDevice, ROLE_ADMIN
from security import roles_required, record_access
import risk as risk_engine

zerotrust_bp = Blueprint("zerotrust", __name__)


@zerotrust_bp.route("/api/risk-events", methods=["GET"])
@roles_required(ROLE_ADMIN)
def list_risk_events():
    rows = RiskEvent.query.order_by(RiskEvent.timestamp.desc()).limit(100).all()
    return jsonify([r.to_dict() for r in rows])


@zerotrust_bp.route("/api/risk-metrics", methods=["GET"])
@roles_required(ROLE_ADMIN)
def risk_metrics():
    since = datetime.utcnow() - timedelta(minutes=60)
    active = [s for s in SessionToken.query.all() if s.is_active()]
    return jsonify({
        "active_sessions": len(active),
        "high_risk_sessions": len([s for s in active if s.risk_level == "HIGH"]),
        "trusted_devices": TrustedDevice.query.filter_by(trusted=True).count(),
        "known_devices": TrustedDevice.query.count(),
        "revocations": SessionToken.query.filter_by(revoked=True).count(),
        "step_ups_1h": RiskEvent.query.filter(
            RiskEvent.decision == "STEP_UP", RiskEvent.timestamp >= since
        ).count(),
        "high_events_1h": RiskEvent.query.filter(
            RiskEvent.level == "HIGH", RiskEvent.timestamp >= since
        ).count(),
        "generated_at": datetime.utcnow().isoformat(),
    })


@zerotrust_bp.route("/api/sessions", methods=["GET"])
@roles_required(ROLE_ADMIN)
def list_sessions():
    rows = SessionToken.query.order_by(SessionToken.created_at.desc()).limit(100).all()
    return jsonify([s.to_dict() for s in rows])


@zerotrust_bp.route("/api/sessions/<int:session_id>/revoke", methods=["POST"])
@roles_required(ROLE_ADMIN)
def revoke_session(session_id):
    session = SessionToken.query.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    risk_engine.revoke_session(session, "Revoked by administrator")
    record_access(get_jwt_identity(), "REVOKE_SESSION",
                  f"session:{session.username}", "SUCCESS")
    return jsonify({"message": f"Session for {session.username} revoked",
                    "session": session.to_dict()})


@zerotrust_bp.route("/api/devices", methods=["GET"])
@roles_required(ROLE_ADMIN)
def list_devices():
    rows = TrustedDevice.query.order_by(TrustedDevice.last_seen.desc()).limit(100).all()
    return jsonify([d.to_dict() for d in rows])


@zerotrust_bp.route("/api/devices/<int:device_id>/trust", methods=["POST"])
@roles_required(ROLE_ADMIN)
def trust_device(device_id):
    dev = TrustedDevice.query.get(device_id)
    if not dev:
        return jsonify({"error": "Device not found"}), 404
    dev.trusted = True
    db.session.commit()
    record_access(get_jwt_identity(), "TRUST_DEVICE", f"device:{dev.username}", "SUCCESS")
    return jsonify({"message": "Device trusted", "device": dev.to_dict()})


@zerotrust_bp.route("/api/devices/<int:device_id>/untrust", methods=["POST"])
@roles_required(ROLE_ADMIN)
def untrust_device(device_id):
    dev = TrustedDevice.query.get(device_id)
    if not dev:
        return jsonify({"error": "Device not found"}), 404
    dev.trusted = False
    db.session.commit()
    record_access(get_jwt_identity(), "UNTRUST_DEVICE", f"device:{dev.username}", "SUCCESS")
    return jsonify({"message": "Device trust revoked — step-up will be required next time",
                    "device": dev.to_dict()})


@zerotrust_bp.route("/api/logout", methods=["POST"])
@jwt_required()
def logout():
    """Revoke the caller's own session (real logout on a stateless JWT)."""
    jti = get_jwt().get("jti")
    session = risk_engine.session_for_jti(jti)
    if session:
        risk_engine.revoke_session(session, "User logout")
    record_access(get_jwt_identity(), "LOGOUT", "SYSTEM", "SUCCESS")
    return jsonify({"message": "Logged out — session revoked."})
