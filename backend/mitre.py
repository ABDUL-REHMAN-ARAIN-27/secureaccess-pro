"""
MITRE ATT&CK mapping — threat-intelligence layer.

Each security detection the system already produces (brute-force, privilege
probing, account lockout, malicious/suspicious file upload, behavioural anomaly,
audit tampering, request flooding) is mapped to the corresponding technique in
the globally recognised MITRE ATT&CK knowledge base. This turns a list of local
alerts into standardised threat intelligence that a SOC analyst / examiner can
immediately recognise, and lets the dashboard report ATT&CK "coverage".

Reference: https://attack.mitre.org/
"""

# alert-type (as produced by the alert engine)  ->  ATT&CK technique
_MAP = {
    "Brute-force / credential attack": {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
    },
    "Privilege escalation / probing": {
        "id": "T1078", "name": "Valid Accounts", "tactic": "Privilege Escalation",
    },
    "Access rule violation": {
        "id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion",
    },
    "Account locked": {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
    },
    "Malicious file upload": {
        "id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
    },
    "Suspicious file upload": {
        "id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
    },
    "Behavioural anomaly (UEBA)": {
        "id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access",
    },
    "Audit log tampering": {
        "id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion",
    },
    "Request flooding / rate limit": {
        "id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact",
    },
}

_DEFAULT = {"id": "TA0000", "name": "Unmapped activity", "tactic": "General"}
_BASE_URL = "https://attack.mitre.org/techniques/"


def for_alert_type(alert_type: str) -> dict:
    """Return the ATT&CK technique dict (id, name, tactic, url) for an alert type."""
    tech = dict(_MAP.get(alert_type, _DEFAULT))
    tid = tech["id"]
    # Sub-technique ids (T1078.003) link under their parent folder on attack.mitre.org.
    tech["url"] = _BASE_URL + tid.split(".")[0] + "/"
    return tech
