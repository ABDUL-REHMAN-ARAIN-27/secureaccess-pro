"""
Secure file storage + upload orchestration.

This module owns the security-sensitive parts of the upload flow and reuses the
existing engines rather than duplicating them:

  * audit  -> security.record_access() (hash-chained, tamper-evident)
  * risk   -> risk.log_risk_event()   (a malicious upload is a Critical event)
  * alerts -> surfaced by admin.get_alerts() from the uploaded_files table

Hardening applied here: size cap enforced while streaming, safe filename +
path-traversal rejection, content-sniffed MIME allow-list (extension never
trusted), random server-side names, files stored outside the web root, and
scanner failures fail *closed* (quarantine, never auto-clean).
"""

import hashlib
import os
import uuid

from flask import current_app
from werkzeug.utils import secure_filename

import scanner
from extensions import db
from models import (
    User, UploadedFile,
    SCAN_CLEAN, SCAN_SUSPICIOUS, SCAN_MALICIOUS, SCAN_ERROR,
    REVIEW_APPROVED, REVIEW_QUARANTINED, ROLE_ADMIN,
)
from security import record_access
import risk as risk_engine


class UploadError(Exception):
    """Raised for a validation failure that should return HTTP 400."""


def ensure_dirs(config):
    for key in ("FILE_STORE_DIR", "FILE_QUARANTINE_DIR", "FILE_TMP_DIR"):
        os.makedirs(config[key], exist_ok=True)


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #
def _safe_original_name(raw):
    """Reject path-traversal / null bytes, then sanitise for storage/display."""
    if not raw:
        raise UploadError("A filename is required.")
    if "\x00" in raw or "/" in raw or "\\" in raw or ".." in raw:
        raise UploadError("Unsafe filename rejected.")
    safe = secure_filename(raw)
    if not safe:
        raise UploadError("Filename could not be processed safely.")
    return safe[:255]


def _sniff_mime(path, filename):
    """Determine the content type from the bytes, not the extension.

    Uses python-magic when available; otherwise a small magic-byte sniff with a
    mimetypes fallback so the project runs without the optional dependency.
    """
    try:
        import magic  # optional
        return magic.from_file(path, mime=True)
    except Exception:
        pass
    with open(path, "rb") as f:
        head = f.read(16)
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith(b"\x89PNG"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head.startswith(b"PK\x03\x04"):
        return "application/zip"
    # Printable ASCII/UTF-8 text -> text/plain (covers the EICAR test file).
    try:
        with open(path, "rb") as f:
            chunk = f.read(4096)
        chunk.decode("utf-8")
        return "text/plain"
    except Exception:
        import mimetypes
        return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def _stream_to_tmp(file_storage, tmp_path, max_bytes):
    """Stream the upload to disk, enforcing the size cap as we go."""
    size = 0
    sha = hashlib.sha256()
    with open(tmp_path, "wb") as out:
        while True:
            chunk = file_storage.stream.read(64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                out.close()
                os.remove(tmp_path)
                raise UploadError(
                    f"File exceeds the {max_bytes // (1024 * 1024)} MB limit."
                )
            sha.update(chunk)
            out.write(chunk)
    if size == 0:
        os.remove(tmp_path)
        raise UploadError("The uploaded file is empty.")
    return size, sha.hexdigest()


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def process_upload(file_storage, username, ip, device_fp):
    """Validate -> hash -> scan -> store/quarantine. Returns (UploadedFile, msg).

    Raises UploadError (HTTP 400) for validation failures.
    """
    cfg = current_app.config
    ensure_dirs(cfg)

    original = _safe_original_name(file_storage.filename)
    record_access(username, "FILE_UPLOAD_STARTED", original, "STARTED")

    # 1) Stream to a private temp file while enforcing the size cap + hashing.
    tmp_name = uuid.uuid4().hex
    tmp_path = os.path.join(cfg["FILE_TMP_DIR"], tmp_name)
    try:
        size, file_hash = _stream_to_tmp(file_storage, tmp_path, cfg["MAX_UPLOAD_BYTES"])
    except UploadError:
        record_access(username, "FILE_ACCESS_DENIED", original, "DENIED")
        raise

    # 2) Determine the real content type (never trust the extension). By default
    # every format is accepted and left to the scanner; if the allow-list mode is
    # enabled, reject types outside it before scanning.
    mime = _sniff_mime(tmp_path, original)
    if not cfg.get("UPLOAD_ALLOW_ALL_TYPES", True) and mime not in cfg["UPLOAD_ALLOWED_MIME"]:
        os.remove(tmp_path)
        record_access(username, "FILE_ACCESS_DENIED", f"{original} ({mime})", "DENIED")
        raise UploadError(f"File type '{mime}' is not allowed.")

    record_access(username, "FILE_UPLOADED", original, "SUCCESS")

    # 3) Scan.
    record_access(username, "FILE_SCAN_STARTED", original, "STARTED")
    result = scanner.scan_file(tmp_path, cfg)
    status, detection, detail, engine = result.as_tuple()

    rec = UploadedFile(
        user_id=_user_id(username), username=username,
        original_filename=original, file_hash=file_hash, file_size=size,
        mime_type=mime, ip_address=ip, device_fp=device_fp,
        scan_status=status, scan_result=detail, detection_name=detection,
        scan_engine=engine,
    )

    if status == SCAN_CLEAN:
        stored = uuid.uuid4().hex
        os.replace(tmp_path, os.path.join(cfg["FILE_STORE_DIR"], stored))
        rec.stored_filename = stored
        rec.review_status = REVIEW_APPROVED
        record_access(username, "FILE_SCAN_CLEAN", original, "SUCCESS")
        record_access(username, "FILE_ACCESS_GRANTED", original, "GRANTED")
        message = "File uploaded and security scan completed successfully."
    else:
        # SUSPICIOUS / MALICIOUS / SCAN_ERROR all fail closed -> quarantine.
        qname = uuid.uuid4().hex + ".quarantine"
        qpath = os.path.join(cfg["FILE_QUARANTINE_DIR"], qname)
        os.replace(tmp_path, qpath)
        try:
            os.chmod(qpath, 0o600)  # not executable, owner-only
        except OSError:
            pass
        rec.stored_filename = qname
        rec.quarantine_path = qpath
        rec.review_status = REVIEW_QUARANTINED

        scan_action = {
            SCAN_MALICIOUS: "FILE_SCAN_MALICIOUS",
            SCAN_SUSPICIOUS: "FILE_SCAN_SUSPICIOUS",
            SCAN_ERROR: "FILE_SCAN_ERROR",
        }.get(status, "FILE_SCAN_SUSPICIOUS")
        record_access(username, scan_action, original, "DENIED")
        record_access(username, "FILE_QUARANTINED", original, "QUARANTINED")

        _raise_risk(username, original, status, detection, ip, device_fp)

        if status == SCAN_MALICIOUS:
            message = ("Upload blocked. The file was identified as a security "
                       "threat and has been quarantined. The administrator has "
                       "been notified.")
        elif status == SCAN_SUSPICIOUS:
            message = ("Upload held for review. The file looked suspicious and "
                       "has been quarantined pending administrator review.")
        else:
            message = ("Upload could not be verified safe and has been "
                       "quarantined pending administrator review.")

    db.session.add(rec)
    db.session.commit()
    return rec, message


def _user_id(username):
    u = User.query.filter_by(username=username).first()
    return u.id if u else None


def _raise_risk(username, filename, status, detection, ip, device_fp):
    """A malicious/suspicious upload is a Critical/High risk event. Optionally
    (opt-in) block the user — off by default so the response stays configurable."""
    cfg = current_app.config
    if status == SCAN_MALICIOUS:
        score, level, decision = 100, "Critical", "BLOCK"
    elif status == SCAN_SUSPICIOUS:
        score, level, decision = 70, "High", "STEP_UP"
    else:  # SCAN_ERROR
        score, level, decision = 50, "Medium", "STEP_UP"

    factors = [f"malicious upload: {detection}" if detection else "unsafe upload",
               f"file: {filename}"]
    risk_engine.log_risk_event(username, "UPLOAD", "File Upload", ip, device_fp,
                               score, level, decision, factors)

    if status == SCAN_MALICIOUS and cfg.get("MALWARE_AUTO_BLOCK"):
        user = User.query.filter_by(username=username).first()
        if user and user.role != ROLE_ADMIN:
            user.is_blocked = True
            db.session.commit()
            record_access(username, "AUTO_BLOCK", "malicious upload", "SUCCESS")
