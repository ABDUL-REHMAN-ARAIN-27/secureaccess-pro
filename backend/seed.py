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
from extensions import db
from models import User, ROLE_ADMIN, ROLE_USER, ROLE_VIEWER

DEMO_USERS = [
    # username,        email,                          password,          role
    ("Abdul Rehman", "abdulrehmanarainmanni@gmail.com", "AbdulRehman2711", ROLE_ADMIN),
    ("user",         "user@secureaccess.pro",           "User@123",        ROLE_USER),
    ("viewer",       "viewer@secureaccess.pro",         "Viewer@123",      ROLE_VIEWER),
]


def seed(reset=False):
    app = create_app()
    with app.app_context():
        if reset:
            print("Dropping all tables ...")
            db.drop_all()
            db.create_all()

        created = []
        for username, email, password, role in DEMO_USERS:
            existing = User.query.filter_by(username=username).first()
            if existing:
                print(f"  - {username!r} already exists, skipping")
                continue
            u = User(
                username=username,
                email=email,
                role=role,
                totp_secret=User.new_totp_secret(),
            )
            u.set_password(password)
            db.session.add(u)
            created.append((u, password))

        db.session.commit()

        print("\n" + "=" * 68)
        print("SecureAccess Pro - demo accounts")
        print("=" * 68)
        for u in User.query.order_by(User.id).all():
            pwd = next((p for created_u, p in created if created_u.id == u.id), "(unchanged)")
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
