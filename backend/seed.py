"""
Seed the database with the three demo accounts (Admin / User / Viewer).

Each account gets a bcrypt-hashed password and a unique TOTP secret. The
provisioning URIs printed below can be added to Google Authenticator / Authy,
or the current 6-digit code can be read directly for a quick demo.

Usage:
    python seed.py            # create demo users if they do not exist
    python seed.py --reset    # drop & recreate all tables first
"""

import sys

from app import create_app
from bootstrap import seed_demo
from models import User, Patient


def seed(reset=False):
    app = create_app()
    created = seed_demo(app, reset=reset)
    pwd_by_user = dict(created)
    with app.app_context():
        print(f"  + {Patient.query.count()} patient records present")
        print("\n" + "=" * 68)
        print("SecureAccess Pro - demo accounts")
        print("=" * 68)
        for u in User.query.order_by(User.id).all():
            pwd = pwd_by_user.get(u.username, "(unchanged)")
            print(f"\nRole     : {u.role}")
            print(f"Username : {u.username}")
            print(f"Password : {pwd}")
            print(f"TOTP now : {u.current_totp(interval=app.config['TOTP_INTERVAL'])}  (changes every 30s)")
            print(f"OTP URI  : {u.provisioning_uri(issuer=app.config['TOTP_ISSUER'], interval=app.config['TOTP_INTERVAL'])}")
        print("\n" + "=" * 68)
        print("Add the OTP URI to an authenticator app, or use the demo helper:")
        print("    python show_code.py <username>")
        print("=" * 68)


if __name__ == "__main__":
    seed(reset="--reset" in sys.argv)
