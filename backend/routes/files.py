"""
Secure File Upload + Malware Detection blueprint.

Zero Trust integration: uploading and downloading are guarded by both
@roles_required (RBAC) and @continuous_verify (live risk / session revocation),
so a blocked or high-risk session cannot upload even with a valid token — and a
malicious file is quarantined regardless of who uploaded it.

    Users  : upload, list own files, download own approved/clean files.
    Admins : file-security monitor, metrics, review (approve/reject/keep).
"""

import os

from flask import Blueprint, current_app, jsonify, request, send_file
from flask_jwt_extended import get_jwt, get_jwt_identity

import filevault
import risk as risk_engine
from extensions import db
from filevault import UploadError
from models import (
    UploadedFile, User,
    SCAN_CLEAN, SCAN_SUSPICIOUS, SCAN_MALICIOUS, SCAN_ERROR,
    REVIEW_APPROVED, REVIEW_REJECTED, REVIEW_QUARANTINED,
    ROLE_ADMIN, ROLE_USER,
)
from security import roles_required, continuous_verify, record_access, resolve_ip

files_bp = Blueprint("files", __name__)


def _context():
    """(username, ip, device_fp) for the current request."""
    username = get_jwt_identity()
    ip = resolve_ip(username)
    device_fp = risk_engine.device_fingerprint(username, risk_engine.read_device_id())
    return username, ip, device_fp


# --------------------------------------------------------------------------- #
# User-facing endpoints
# --------------------------------------------------------------------------- #
@files_bp.route("/api/files/upload", methods=["POST"])
@roles_required(ROLE_ADMIN, ROLE_USER)
@continuous_verify("File Upload")
def upload_file():
    if "file" not in request.files or request.files["file"].filename == "":
        return jsonify({"error": "No file was provided."}), 400

    username, ip, device_fp = _context()
    try:
        rec, message = filevault.process_upload(request.files["file"], username, ip, device_fp)
    except UploadError as exc:
        return jsonify({"error": str(exc)}), 400

    # Ordinary users get a safe status only — never internal malware details.
    safe = {
        "id": rec.id,
        "original_filename": rec.original_filename,
        "scan_status": rec.scan_status,
        "review_status": rec.review_status,
        "downloadable": rec.is_downloadable(),
    }
    blocked = rec.scan_status in (SCAN_MALICIOUS, SCAN_SUSPICIOUS, SCAN_ERROR)
    return jsonify({"message": message, "blocked": blocked, "file": safe}), 201


@files_bp.route("/api/files", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER)
def list_my_files():
    username = get_jwt_identity()
    rows = (UploadedFile.query.filter_by(username=username)
            .order_by(UploadedFile.upload_time.desc()).limit(100).all())
    # Owner view hides the raw detection signature (kept for the admin monitor).
    return jsonify([r.to_dict(include_hash=True) | {"detection_name": None} for r in rows])


@files_bp.route("/api/files/<int:file_id>/download", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER)
@continuous_verify("File Upload")
def download_file(file_id):
    username = get_jwt_identity()
    role = get_jwt().get("role", "")
    rec = UploadedFile.query.get(file_id)
    if not rec:
        return jsonify({"error": "File not found."}), 404

    # A user may only reach their own files; the admin may reach any.
    if role != ROLE_ADMIN and rec.username != username:
        record_access(username, "FILE_ACCESS_DENIED", rec.original_filename, "DENIED")
        return jsonify({"error": "Access denied."}), 403

    if not rec.is_downloadable():
        record_access(username, "FILE_ACCESS_DENIED", rec.original_filename, "DENIED")
        return jsonify({"error": "This file is not available. It is quarantined "
                                 "or pending review."}), 403

    path = _resolve_path(rec)
    if not path or not os.path.exists(path):
        return jsonify({"error": "File is no longer available."}), 404

    record_access(username, "FILE_ACCESS_GRANTED", rec.original_filename, "GRANTED")
    # Always an attachment with a generic type — never rendered/executed inline.
    return send_file(path, as_attachment=True, download_name=rec.original_filename,
                     mimetype="application/octet-stream")


def _resolve_path(rec):
    cfg = current_app.config
    if rec.scan_status == SCAN_CLEAN:
        return os.path.join(cfg["FILE_STORE_DIR"], rec.stored_filename or "")
    return rec.quarantine_path  # admin-approved suspicious file


# --------------------------------------------------------------------------- #
# Admin file-security monitor
# --------------------------------------------------------------------------- #
@files_bp.route("/api/admin/files", methods=["GET"])
@roles_required(ROLE_ADMIN)
def admin_list_files():
    rows = UploadedFile.query.order_by(UploadedFile.upload_time.desc()).limit(100).all()
    return jsonify([r.to_dict(include_hash=True) for r in rows])


@files_bp.route("/api/admin/file-metrics", methods=["GET"])
@roles_required(ROLE_ADMIN)
def admin_file_metrics():
    q = UploadedFile.query
    return jsonify({
        "total": q.count(),
        "clean": q.filter_by(scan_status=SCAN_CLEAN).count(),
        "suspicious": q.filter_by(scan_status=SCAN_SUSPICIOUS).count(),
        "malicious": q.filter_by(scan_status=SCAN_MALICIOUS).count(),
        "scan_errors": q.filter_by(scan_status=SCAN_ERROR).count(),
        "quarantined": q.filter_by(review_status=REVIEW_QUARANTINED).count(),
        "scanner_mode": current_app.config.get("SCANNER_MODE", "demo"),
    })


@files_bp.route("/api/admin/files/<int:file_id>/review", methods=["POST"])
@roles_required(ROLE_ADMIN)
def admin_review_file(file_id):
    rec = UploadedFile.query.get(file_id)
    if not rec:
        return jsonify({"error": "File not found."}), 404

    decision = (request.get_json(silent=True) or {}).get("decision", "").lower()
    admin = get_jwt_identity()

    if decision == "approve":
        # Safety: a known-malicious file can never be approved for download.
        if rec.scan_status in (SCAN_MALICIOUS, SCAN_ERROR):
            return jsonify({"error": "A malicious or unverified file cannot be approved."}), 400
        rec.review_status = REVIEW_APPROVED
    elif decision == "reject":
        rec.review_status = REVIEW_REJECTED
    elif decision in ("quarantine", "keep"):
        rec.review_status = REVIEW_QUARANTINED
    else:
        return jsonify({"error": "decision must be approve / reject / quarantine."}), 400

    from datetime import datetime
    rec.reviewed_by = admin
    rec.reviewed_at = datetime.utcnow()
    db.session.commit()
    record_access(admin, "ADMIN_REVIEWED_FILE",
                  f"{rec.original_filename}->{rec.review_status}", "SUCCESS")
    return jsonify({"message": f"File marked {rec.review_status}.", "file": rec.to_dict()})
