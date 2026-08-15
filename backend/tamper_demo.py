"""
Tampering demonstration for SecureAccess Pro.

This simulates an attacker who edits the audit log directly in the database to
hide their tracks (e.g. changing a DENIED access to GRANTED). Because every log
entry is SHA-256 hash-chained to the previous one, this edit breaks the chain
and is instantly detectable.

How to demo:
    1. Run the backend (python app.py) and do some activity (log in, etc.).
    2. Run:  python tamper_demo.py
    3. As Admin, open the "Security Alerts" tab -> the Audit Integrity badge
       turns RED: "TAMPERING DETECTED at entry #X".
    4. To reset, run:  python seed.py --reset

Usage:
    python tamper_demo.py            # tamper with one log entry
    python tamper_demo.py --check    # just report integrity, don't tamper
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app                       # noqa: E402
from extensions import db                 # noqa: E402
from models import AccessLog              # noqa: E402
from audit import verify_chain            # noqa: E402


def main():
    check_only = "--check" in sys.argv
    with app.app_context():
        rows = AccessLog.query.order_by(AccessLog.id.asc()).all()
        if not rows:
            print("No audit logs yet. Log in / use the app first, then run this.")
            return

        if check_only:
            r = verify_chain(rows)
            print("Audit integrity:", "VERIFIED (no tampering)" if r["intact"]
                  else f"TAMPERED at entry #{r['broken_at']} — {r['reason']}")
            return

        # Prefer to tamper a DENIED entry -> change it to GRANTED (attacker
        # trying to hide an unauthorized access). Otherwise pick a middle row.
        denied = [r for r in rows if r.status == "DENIED"]
        target = denied[0] if denied else rows[len(rows) // 2]

        print("=" * 60)
        print(" Simulating an attacker editing the audit log ...")
        print("=" * 60)
        print(f"Entry #{target.id} BEFORE tampering:")
        print(f"   {target.username} | {target.action} | {target.resource} | {target.status}")

        # The malicious edit — bypasses the app and writes straight to the DB.
        target.status = "GRANTED"
        target.resource = "Finance Dashboard"
        db.session.commit()

        print(f"Entry #{target.id} AFTER tampering (hacker changed it):")
        print(f"   {target.username} | {target.action} | {target.resource} | {target.status}")

        result = verify_chain(AccessLog.query.order_by(AccessLog.id.asc()).all())
        print("\nSystem check:", "STILL INTACT?!" if result["intact"]
              else f"TAMPERING DETECTED at entry #{result['broken_at']}")
        print(f"Reason: {result['reason']}")
        print("\nNow open Admin -> Security Alerts: the Audit Integrity badge is RED.")
        print("Reset everything with:  python seed.py --reset")


if __name__ == "__main__":
    main()
