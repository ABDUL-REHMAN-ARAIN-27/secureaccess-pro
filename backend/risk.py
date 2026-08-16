"""
Phase 2 — Risk Engine + Policy Engine (the "brain" of the upgraded Zero Trust
flow).

The original system was:   Login -> MFA -> RBAC -> Access
This module turns it into:  Identity -> MFA -> Device -> Context -> Risk Score
                            -> Policy Engine -> Decision -> Continuous Verification

Nothing here trusts a request just because a valid token was presented. Every
sensitive access is re-scored from live signals (device, IP, account state,
resource sensitivity) and the policy engine decides: ALLOW, STEP_UP (re-MFA),
or REVOKE (kill the session) — automatically.
"""

import hashlib
from datetime import datetime

from flask import current_app, request

from extensions import db
from models import TrustedDevice, SessionToken, RiskEvent, LoginHistory, ROLE_ADMIN

# CVSS v3 severity ratings.
NONE, LOW, MEDIUM, HIGH, CRITICAL = "None", "Low", "Medium", "High", "Critical"


def cvss_of(score):
    """Express the internal 0-100 risk score on the CVSS 0.0-10.0 scale."""
    return round(min(max(score, 0), 100) / 10.0, 1)


# --------------------------------------------------------------------------- #
# Device fingerprint
# --------------------------------------------------------------------------- #
def read_device_id():
    """Client-supplied opaque device id (body field or header). The browser app
    generates a random id once and keeps it in localStorage; it is never PII."""
    data = request.get_json(silent=True) or {}
    return (
        data.get("device_id")
        or request.headers.get("X-Device-Id")
        or ""
    ).strip()


def device_fingerprint(username, device_id):
    """Stable, non-reversible fingerprint bound to both the device id and the
    user, so the same browser looks different across accounts."""
    raw = f"{username}::{device_id or 'no-device'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _short_ua():
    ua = request.headers.get("User-Agent", "Unknown")
    for name in ("Edg", "Chrome", "Firefox", "Safari"):
        if name in ua:
            browser = "Edge" if name == "Edg" else name
            break
    else:
        browser = "Unknown browser"
    os_name = next((o for o in ("Windows", "Mac", "Linux", "Android", "iPhone") if o in ua), "")
    return f"{browser}{(' on ' + os_name) if os_name else ''}"


def lookup_device(username, device_fp):
    return TrustedDevice.query.filter_by(username=username, device_fp=device_fp).first()


def register_device(username, device_fp, ip, trust=True):
    """Record/refresh a device sighting. New devices start untrusted; after a
    full MFA login we mark them trusted (trust=True)."""
    dev = lookup_device(username, device_fp)
    now = datetime.utcnow()
    if dev is None:
        dev = TrustedDevice(
            username=username, device_fp=device_fp, label=_short_ua(),
            trusted=bool(trust), first_seen=now, last_seen=now, last_ip=ip,
        )
        db.session.add(dev)
    else:
        dev.last_seen = now
        dev.last_ip = ip
        if trust:
            dev.trusted = True
    return dev


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def _band(score):
    """Map a 0-100 score to a CVSS v3 severity rating."""
    cfg = current_app.config
    if score <= 0:
        return NONE
    if score >= cfg["RISK_CRITICAL"]:
        return CRITICAL
    if score >= cfg["RISK_HIGH"]:
        return HIGH
    if score >= cfg["RISK_MEDIUM"]:
        return MEDIUM
    return LOW


def _ip_seen_before(username, ip):
    return (
        LoginHistory.query.filter_by(username=username, status="SUCCESS")
        .filter(LoginHistory.ip_address == ip)
        .first()
        is not None
    )


def score_login(user, ip, device_fp):
    """Score an authentication attempt (called after password+MFA succeed).
    Returns (score, level, factors, known_device)."""
    cfg = current_app.config

    # The administrator is the trusted authority that operates the system — it
    # is never subjected to risk scoring / step-up / revocation. Risk-based
    # access control applies to User and Viewer accounts only.
    if user.role == ROLE_ADMIN:
        return 0, NONE, ["administrator account (trusted)"], True

    score = 0
    factors = []

    dev = lookup_device(user.username, device_fp)
    known_device = bool(dev and dev.trusted)
    if not known_device:
        score += cfg["RISK_WEIGHT_NEW_DEVICE"]
        factors.append("new / untrusted device")

    if not _ip_seen_before(user.username, ip):
        score += cfg["RISK_WEIGHT_NEW_IP"]
        factors.append("first login from this IP")

    recent_failures = min(user.failed_attempts or 0, 3)
    if recent_failures:
        score += recent_failures * cfg["RISK_WEIGHT_FAILED"]
        factors.append(f"{recent_failures} recent failed attempt(s)")

    hour = datetime.utcnow().hour
    if hour < 6 or hour >= 22:
        score += cfg["RISK_WEIGHT_OFFHOURS"]
        factors.append("off-hours access")

    if user.is_blocked:
        score += cfg["RISK_WEIGHT_BLOCKED"]
        factors.append("account is blocked")

    # UEBA — behaviour-based adaptive anomaly (explainable), added on top of the
    # rule-based signals. Learns each user's normal pattern; silent at cold start.
    try:
        import ueba
        ueba_score, ueba_factors = ueba.evaluate(user.username)
        score += ueba_score
        factors.extend(ueba_factors)
    except Exception:  # pragma: no cover - UEBA must never break login scoring
        pass

    score = min(score, 100)
    return score, _band(score), factors, known_device


def score_access(user, resource, session):
    """Continuous verification: re-score a sensitive access against the live
    session. Returns (score, level, factors)."""
    cfg = current_app.config

    # Administrator is trusted — its own access is never risk-blocked.
    if user.role == ROLE_ADMIN:
        return 0, NONE, ["administrator account (trusted)"]

    score = 0
    factors = []

    sensitivity = cfg["RISK_SENSITIVITY"].get(resource, 0)
    if sensitivity:
        score += sensitivity
        factors.append(f"sensitive resource ({resource})")

    # Account state can change *after* a token was issued — the whole point of
    # continuous verification vs. a plain stateless JWT.
    if user.is_blocked:
        score += cfg["RISK_WEIGHT_BLOCKED"]
        factors.append("account blocked since login")
    if user.is_locked():
        score += cfg["RISK_WEIGHT_LOCKED"]
        factors.append("account locked since login")

    # A device an admin has un-trusted (or that was never trusted) elevates the
    # score enough, together with resource sensitivity, to require step-up.
    cur_fp = device_fingerprint(user.username, read_device_id())
    dev = lookup_device(user.username, cur_fp)
    if sensitivity and not (dev and dev.trusted):
        score += cfg["RISK_WEIGHT_UNTRUSTED_AT_ACCESS"]
        factors.append("access from an untrusted device")

    if session:
        if session.device_fp and cur_fp != session.device_fp:
            score += cfg["RISK_WEIGHT_DEVICE_MISMATCH"]
            factors.append("device changed mid-session")
        # IP change is only meaningful if we can resolve a real one.
        from security import resolve_ip
        cur_ip = resolve_ip(user.username)
        if session.ip_address and cur_ip != session.ip_address:
            score += cfg["RISK_WEIGHT_IP_MISMATCH"]
            factors.append("source IP changed mid-session")

    score = min(score, 100)
    return score, _band(score), factors


# --------------------------------------------------------------------------- #
# Policy engine — turn a risk band into a decision
# --------------------------------------------------------------------------- #
def decide(phase, level):
    """LOGIN vs ACCESS have different policies.

    LOGIN happens right after MFA, so even an elevated score is ALLOWed (the
    second factor already passed) but recorded/flagged. ACCESS is continuous:
    MEDIUM asks for step-up re-verification, HIGH revokes the session.
    """
    if phase == "LOGIN":
        return "ALLOW"
    if level in (HIGH, CRITICAL):
        return "REVOKE"
    if level == MEDIUM:
        return "STEP_UP"
    return "ALLOW"  # None / Low


# --------------------------------------------------------------------------- #
# Persistence helpers
# --------------------------------------------------------------------------- #
def log_risk_event(username, phase, resource, ip, device_fp, score, level, decision, factors):
    try:
        db.session.add(RiskEvent(
            username=username, phase=phase, resource=resource, ip_address=ip,
            device_fp=device_fp, score=score, level=level, decision=decision,
            factors="; ".join(factors) if factors else "no risk signals",
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()


def create_session(jti, user, device_fp, ip, score, level, expires_at):
    try:
        db.session.add(SessionToken(
            jti=jti, username=user.username, role=user.role, device_fp=device_fp,
            ip_address=ip, risk_score=score, risk_level=level, expires_at=expires_at,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()


def revoke_session(session, reason):
    try:
        session.revoked = True
        session.revoked_reason = reason
        db.session.commit()
    except Exception:
        db.session.rollback()


def session_for_jti(jti):
    if not jti:
        return None
    return SessionToken.query.filter_by(jti=jti).first()
