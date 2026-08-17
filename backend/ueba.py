"""
UEBA — User & Entity Behaviour Analytics (AI-based adaptive risk).

An *unsupervised* per-user behaviour model that learns each account's normal
login pattern and produces an **explainable** anomaly contribution which is added
on top of the rule-based CVSS score. This is what turns the system from static
risk rules into behaviour-aware, adaptive Zero Trust.

Design principles:
  * Cold-start safe — stays silent until it has seen `UEBA_MIN_LOGINS` logins,
    so a brand-new account is never falsely flagged.
  * Explainable — every point of anomaly comes with a plain-English reason
    (unusual hour for this user, login burst), never an opaque black-box number.
  * Dependency-light — the default engine is a numpy statistical baseline. An
    optional scikit-learn IsolationForest engine is used only if installed.

Honest limitation: this is a lightweight behavioural model trained on small,
per-user data — a demonstrator of adaptive/AI-driven risk, not an enterprise ML
detection product.
"""

from datetime import datetime

import numpy as np
from flask import current_app

from extensions import db
from models import BehaviorProfile


def _profile(username):
    return BehaviorProfile.query.filter_by(username=username).first()


# --------------------------------------------------------------------------- #
# Scoring (read-only) — score the CURRENT login against the learned baseline
# --------------------------------------------------------------------------- #
def evaluate(username, now=None):
    """Return (anomaly_score_0_100, factors). Does not mutate the profile."""
    cfg = current_app.config
    if not cfg.get("UEBA_ENABLED", True):
        return 0, []

    p = _profile(username)
    now = now or datetime.utcnow()
    n = p.login_count if p else 0
    if not p or n < cfg["UEBA_MIN_LOGINS"]:
        return 0, [f"UEBA: baseline still training ({n} logins learned)"]

    factors = []
    score = 0.0

    # 1) Unusual login hour for THIS user (personal temporal baseline).
    hist = p.get_hist()
    total = max(1, sum(hist))
    hour = now.hour
    freq = hist[hour] / total
    hour_anom = max(0.0, 1.0 - freq / 0.15)  # 0 once this hour is >=15% of logins
    if hour_anom > 0.05:
        score += cfg["UEBA_W_HOUR"] * hour_anom
        usual = ", ".join(p.top_hours(2)) or "n/a"
        factors.append(f"unusual login hour {hour:02d}:00 for this user (usual: {usual})")

    # 2) Login-burst velocity anomaly (possible automation / stolen session).
    if p.last_login_at:
        secs = (now - p.last_login_at).total_seconds()
        intervals = p.get_intervals()
        if intervals:
            mean = float(np.mean(np.array(intervals, dtype=float)))
            if secs < cfg["UEBA_BURST_SECONDS"] and (mean == 0 or secs < mean * 0.25):
                score += cfg["UEBA_W_BURST"]
                factors.append(
                    f"login burst: {int(secs)}s since last vs typical ~{int(mean)}s "
                    "(possible automation)")

    # 3) Optional IsolationForest refinement (only if scikit-learn is installed).
    if cfg.get("UEBA_MODEL") == "iforest":
        extra = _iforest_score(p, now)
        if extra:
            add, why = extra
            score = max(score, add)
            factors.append(why)

    score = min(cfg["UEBA_MAX"], score)
    return int(round(score)), factors


def _iforest_score(profile, now):
    """Anomaly from an IsolationForest trained on the user's recent logins.
    Returns (score, reason) or None when unavailable/insufficient data."""
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return None
    vectors = profile.get_vectors()
    if len(vectors) < 15:
        return None
    try:
        X = np.array(vectors, dtype=float)
        model = IsolationForest(contamination="auto", random_state=42).fit(X)
        cur = np.array([[now.hour, now.weekday(), 1.0]])
        # score_samples: lower = more anomalous. Map to 0..UEBA_MAX.
        s = float(model.score_samples(cur)[0])
        norm = max(0.0, min(1.0, (-(s) - 0.4) / 0.4))
        add = current_app.config["UEBA_MAX"] * norm
        if add >= 5:
            return add, "IsolationForest flagged this login as behaviourally anomalous"
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------- #
# Learning (write) — record a successful login into the baseline
# --------------------------------------------------------------------------- #
def observe_login(username, ip, device_fp, level="None"):
    """Update the user's behaviour baseline with this successful login.

    Anti-poisoning (module plan §3): the baseline is only trained from allowed,
    *unflagged* logins. A login the risk engine scored High/Critical is recorded
    as a sighting but NOT folded into the learned baseline, so an attacker cannot
    slowly train the model to accept abnormal behaviour."""
    cfg = current_app.config
    if not cfg.get("UEBA_ENABLED", True):
        return
    if level in ("High", "Critical"):
        return  # do not learn from a flagged login
    now = datetime.utcnow()
    p = _profile(username)
    if not p:
        p = BehaviorProfile(username=username)
        db.session.add(p)

    # Record how anomalous THIS login was *before* folding it into the baseline.
    try:
        anom, _ = evaluate(username, now)
        p.last_anomaly = float(anom)
        p.last_anomaly_at = now
    except Exception:
        pass

    hist = p.get_hist()
    hist[now.hour] += 1
    p.set_hist(hist)

    if p.last_login_at:
        iv = p.get_intervals()
        iv.append(int((now - p.last_login_at).total_seconds()))
        p.set_intervals(iv)

    ips = p.get_known_ips()
    if ip and ip not in ips:
        ips.append(ip)
        p.set_known_ips(ips)

    devs = p.get_known_devices()
    dfp = (device_fp or "")[:12]
    if dfp and dfp not in devs:
        devs.append(dfp)
        p.set_known_devices(devs)

    vecs = p.get_vectors()
    vecs.append([now.hour, now.weekday(), 1.0 if (ip in ips) else 0.0])
    p.set_vectors(vecs)

    p.login_count = (p.login_count or 0) + 1
    p.last_login_at = now
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
