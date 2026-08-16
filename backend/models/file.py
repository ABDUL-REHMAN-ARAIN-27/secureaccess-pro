"""
Secure File Upload model.

One row per uploaded file. The record tracks the full security lifecycle:
    validation -> SHA-256 -> scan -> (approved store | quarantine) -> review.

`scan_status`   is the scanner's verdict (PENDING_SCAN / CLEAN / SUSPICIOUS /
                MALICIOUS / SCAN_ERROR).
`review_status` is the availability decision (PENDING / APPROVED / REJECTED /
                QUARANTINED). A normal user may only download a file that is
                CLEAN *and* APPROVED.
"""

from datetime import datetime

from extensions import db

# Scanner verdicts.
SCAN_PENDING = "PENDING_SCAN"
SCAN_CLEAN = "CLEAN"
SCAN_SUSPICIOUS = "SUSPICIOUS"
SCAN_MALICIOUS = "MALICIOUS"
SCAN_ERROR = "SCAN_ERROR"

# Availability decisions.
REVIEW_PENDING = "PENDING"
REVIEW_APPROVED = "APPROVED"
REVIEW_REJECTED = "REJECTED"
REVIEW_QUARANTINED = "QUARANTINED"


class UploadedFile(db.Model):
    __tablename__ = "uploaded_files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(50), index=True)  # denormalised for logs/alerts

    original_filename = db.Column(db.String(255))
    stored_filename = db.Column(db.String(120))       # random, server-side name
    file_hash = db.Column(db.String(64), index=True)  # SHA-256 hex
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(120))

    upload_time = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address = db.Column(db.String(64))
    device_fp = db.Column(db.String(64))

    scan_status = db.Column(db.String(20), default=SCAN_PENDING)
    scan_result = db.Column(db.String(255))           # human-readable detail
    detection_name = db.Column(db.String(120))        # signature name if any
    scan_engine = db.Column(db.String(40))            # demo / clamav

    quarantine_path = db.Column(db.String(255))       # set only when quarantined
    review_status = db.Column(db.String(20), default=REVIEW_PENDING)
    reviewed_by = db.Column(db.String(50))
    reviewed_at = db.Column(db.DateTime)

    def is_downloadable(self):
        """Served to its owner only when APPROVED and not a threat. A CLEAN file
        is auto-approved; a SUSPICIOUS file becomes downloadable only if an admin
        explicitly approves it. MALICIOUS / SCAN_ERROR files are never served."""
        return (
            self.review_status == REVIEW_APPROVED
            and self.scan_status in (SCAN_CLEAN, SCAN_SUSPICIOUS)
        )

    def to_dict(self, include_hash=True):
        d = {
            "id": self.id,
            "username": self.username,
            "original_filename": self.original_filename,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "upload_time": self.upload_time.isoformat() if self.upload_time else None,
            "ip_address": self.ip_address,
            "scan_status": self.scan_status,
            "scan_result": self.scan_result,
            "detection_name": self.detection_name,
            "scan_engine": self.scan_engine,
            "review_status": self.review_status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "downloadable": self.is_downloadable(),
        }
        if include_hash:
            d["file_hash"] = self.file_hash
        return d
