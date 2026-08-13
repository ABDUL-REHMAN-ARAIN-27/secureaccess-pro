"""
Tamper-evident audit trail helpers.

Every AccessLog row stores the SHA-256 hash of its own contents chained with the
previous row's hash (like a mini blockchain). Recomputing the chain reveals
whether any historical row was modified or deleted — giving the immutable audit
record described in the project's threat model.
"""

import hashlib

GENESIS = "GENESIS"


def compute_entry_hash(prev_hash, username, action, resource, status, ip, ts_iso):
    payload = "|".join([
        prev_hash or GENESIS,
        username or "",
        action or "",
        resource or "",
        status or "",
        ip or "",
        ts_iso or "",
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain(rows):
    """
    Verify a list of AccessLog rows ordered by id ascending.

    Returns a dict: {intact: bool, total: int, broken_at: id|None, reason: str}.
    """
    prev = GENESIS
    for row in rows:
        ts_iso = row.timestamp.isoformat() if row.timestamp else None
        expected = compute_entry_hash(
            prev, row.username, row.action, row.resource, row.status,
            row.ip_address, ts_iso,
        )
        if row.prev_hash != prev:
            return {"intact": False, "total": len(rows), "broken_at": row.id,
                    "reason": "prev_hash mismatch (a prior row was altered or removed)"}
        if row.entry_hash != expected:
            return {"intact": False, "total": len(rows), "broken_at": row.id,
                    "reason": "entry_hash mismatch (this row's contents were altered)"}
        prev = row.entry_hash
    return {"intact": True, "total": len(rows), "broken_at": None,
            "reason": "Audit chain verified — no tampering detected"}
