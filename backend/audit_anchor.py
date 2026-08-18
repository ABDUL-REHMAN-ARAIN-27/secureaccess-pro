"""
External audit-chain anchoring.

The tamper-evident audit log is a SHA-256 hash chain inside the SQLite database.
An attacker with full write access to that database could, in principle, rewrite
every row and recompute a fresh but internally-consistent chain — the in-DB
verification would then pass.

To close that gap, the latest chain hash is checkpointed to an append-only file
OUTSIDE the database each time a log entry is written. Verification compares the
DB's stored hash for each anchored entry against the externally-recorded value;
a rewrite that changes historical hashes no longer matches the anchor file, so
the tampering is still detected.

Production would place this file on a separate, write-once medium / log host.
"""

import os
from datetime import datetime


def _path():
    from flask import current_app
    return current_app.config.get("AUDIT_ANCHOR_FILE")


def anchor(entry_id, entry_hash):
    """Append one checkpoint line: <utc-iso>\\t<entry_id>\\t<entry_hash>."""
    path = _path()
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.utcnow().isoformat()}\t{entry_id}\t{entry_hash}\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception:  # pragma: no cover - anchoring must never break a request
        pass


def _read_anchors():
    path = _path()
    anchors = []
    if not path or not os.path.exists(path):
        return anchors
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 3:
                    anchors.append((int(parts[1]), parts[2]))
    except Exception:
        pass
    return anchors


def verify_against_db(rows):
    """Compare each anchored (entry_id, hash) with the DB's current hash for that
    entry. Returns {anchored, matched, broken_at, reason}."""
    by_id = {r.id: r.entry_hash for r in rows}
    anchors = _read_anchors()
    for entry_id, anchored_hash in anchors:
        current = by_id.get(entry_id)
        if current is None:
            return {"anchored": len(anchors), "matched": False, "broken_at": entry_id,
                    "reason": f"anchored entry #{entry_id} is missing from the database"}
        if current != anchored_hash:
            return {"anchored": len(anchors), "matched": False, "broken_at": entry_id,
                    "reason": f"entry #{entry_id} hash differs from its external anchor"}
    return {"anchored": len(anchors), "matched": True, "broken_at": None,
            "reason": "all anchored hashes match the database"}
