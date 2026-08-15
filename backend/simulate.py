"""
Live traffic simulator for the SecureAccess Pro demo.

Run this in a SEPARATE terminal while the backend is running. It simulates
several users active at the SAME TIME — normal activity plus some suspicious
behaviour — so the admin's live Security Monitoring fills with activity and
alerts. Great for a live demo / presentation.

What it generates:
  • user   : legit access to HR / Documents / Patients, then tries Finance (DENIED)
  • viewer : legit access to Documents, then tries HR + Finance (DENIED)
  • attacker: repeated failed logins on a victim account (brute-force -> ALERT + lockout)

The repeated DENIED access shows up as "privilege escalation / probing" alerts,
and the failed logins as a "brute-force" alert on the admin dashboard.

Usage:
    python simulate.py            # run continuously (Ctrl+C to stop)
    python simulate.py --once     # a single burst of activity
"""

import os
import sys
import time
import random

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import app          # noqa: E402
from models import User      # noqa: E402

API = os.environ.get("SECUREACCESS_API", "http://127.0.0.1:5000")
_tokens = {}


def totp(username):
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        return u.current_totp() if u else "000000"


def get_token(username, password):
    """Log in once and cache the JWT (valid 15 min)."""
    if username in _tokens:
        return _tokens[username]
    try:
        r = requests.post(f"{API}/api/login", timeout=8,
                          json={"username": username, "password": password,
                                "tfa_code": totp(username)})
        if r.status_code == 200:
            _tokens[username] = r.json()["token"]
            log(f"{username:7s} logged in")
            return _tokens[username]
        log(f"{username:7s} login blocked ({r.status_code})")
    except requests.RequestException:
        log("!! cannot reach server — is 'python app.py' running?")
    return None


def visit(username, token, path, label):
    if not token:
        return
    try:
        r = requests.get(f"{API}{path}", timeout=8,
                        headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 401:          # token expired -> force re-login next time
            _tokens.pop(username, None)
        mark = "GRANTED" if r.status_code == 200 else ("DENIED" if r.status_code == 403 else r.status_code)
        log(f"{username:7s} -> {label:18s} [{mark}]")
    except requests.RequestException:
        pass


def log(msg):
    print(f"  {msg}", flush=True)


def ensure_victim():
    requests.post(f"{API}/api/register", timeout=8, json={
        "username": "victim1", "email": "victim1@example.com",
        "password": "Victim@123", "confirm_password": "Victim@123"})


def normal_activity():
    t = get_token("user", "User@123")
    visit("user", t, "/api/protected/hr", "HR Portal")
    visit("user", t, "/api/protected/documents", "Document Manager")
    visit("user", t, "/api/protected/patients", "Patient Records")
    visit("user", t, "/api/protected/finance", "Finance Dashboard")   # DENIED

    t = get_token("viewer", "Viewer@123")
    visit("viewer", t, "/api/protected/documents", "Document Manager")
    visit("viewer", t, "/api/protected/hr", "HR Portal")              # DENIED
    visit("viewer", t, "/api/protected/finance", "Finance Dashboard") # DENIED


def attack():
    log("attacker: brute-forcing 'victim1' ...")
    for i in range(3):
        try:
            requests.post(f"{API}/api/login", timeout=8, json={
                "username": "victim1", "password": f"wrongpass{i}", "tfa_code": "000000"})
        except requests.RequestException:
            pass
    log("attacker: 3 failed logins sent (should raise a brute-force alert)")


def main():
    once = "--once" in sys.argv
    print("=" * 60)
    print(" SecureAccess Pro — live traffic simulator")
    print(" Open the admin dashboard -> Security Monitoring and watch.")
    print(" Ctrl+C to stop.")
    print("=" * 60)
    ensure_victim()
    rnd = 0
    while True:
        rnd += 1
        print(f"\n--- activity round {rnd} ---")
        normal_activity()
        if rnd % 2 == 0:          # every other round, a suspicious burst
            attack()
        if once:
            break
        time.sleep(random.uniform(6, 9))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
