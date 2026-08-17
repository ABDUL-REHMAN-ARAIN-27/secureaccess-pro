"""
Module 5C — Natural-Language Explanation Generator (the "AI Analyst").

Turns numeric verdicts and raw alerts into auditable, analyst-style English:
each detection gets a plain-language explanation + a recommended action, and a
set of alerts is summarised into a single incident narrative.

Design (from the module plan): this is a **deterministic, template-based** Tier-1
engine — always available, fully reproducible, and it never *makes* a decision;
it only *describes* decisions already taken by the deterministic risk/policy
engine. That boundary keeps the security-critical path auditable and immune to
model error / prompt injection. (An optional local-LLM Tier-2 can layer on top,
but is not required for the contribution.)
"""

from datetime import datetime

# Recommended response per detection type.
_RECO = {
    "Brute-force / credential attack":
        "lock or block the account, confirm with the user, and consider throttling the source IP",
    "Privilege escalation / probing":
        "review the user's role and block the account pending investigation if attempts continue",
    "Access rule violation":
        "confirm the user's permissions and monitor for repeat attempts",
    "Account locked":
        "verify the lockout was legitimate before unlocking",
    "Malicious file upload":
        "keep the file quarantined, do not restore it, and review the uploader's account",
    "Suspicious file upload":
        "review the quarantined file manually before any approval",
    "Audit log tampering":
        "treat as a serious integrity incident, preserve evidence, and investigate administrator access",
    "Behavioural anomaly (UEBA)":
        "require step-up authentication and confirm the session with the user",
    "Request flooding / rate limit":
        "apply stricter rate limits or block the offending source",
}
_DEFAULT_RECO = "review the activity and confirm it is expected"


def recommended_action(alert_type):
    return _RECO.get(alert_type, _DEFAULT_RECO)


def explain_alert(alert):
    """One auditable sentence: what happened, its ATT&CK mapping, and what to do."""
    m = alert.get("mitre") or {}
    tag = ""
    if m.get("id"):
        tag = f" Mapped to MITRE ATT&CK {m['id']} — {m.get('name','')} ({m.get('tactic','')})."
    return (f"{alert.get('detail','Security event')}.{tag} "
            f"Recommended action: {recommended_action(alert.get('type',''))}.")


def narrative(alerts, generated_at=None):
    """A short analyst-style incident summary of the current alerts."""
    ts = (generated_at or datetime.utcnow()).strftime("%Y-%m-%d %H:%M UTC")
    if not alerts:
        return (f"Security summary ({ts}): no active detections. "
                "All recent access is within normal parameters and audit integrity is intact.")

    techniques = sorted({(a.get("mitre") or {}).get("id") for a in alerts if a.get("mitre")})
    high = [a for a in alerts if a.get("severity") == "HIGH"]

    parts = [
        f"Security summary ({ts}): {len(alerts)} active detection(s) "
        f"spanning {len(techniques)} MITRE ATT&CK technique(s) "
        f"[{', '.join(t for t in techniques if t)}]."
    ]
    if high:
        parts.append(f"{len(high)} are high severity and need attention first.")

    # Describe up to the top four, most-severe first (alerts arrive pre-sorted).
    for a in alerts[:4]:
        subj = a.get("subject", "unknown")
        m = a.get("mitre") or {}
        parts.append(
            f"Account '{subj}': {a.get('detail','')} ({m.get('id','')} — {m.get('name','')}); "
            f"recommended to {recommended_action(a.get('type',''))}.")

    if len(alerts) > 4:
        parts.append(f"{len(alerts) - 4} further lower-priority detection(s) are also recorded.")

    parts.append("Every action taken by the system is written to the tamper-evident audit log.")
    return " ".join(parts)
