"""
Shared seeding logic.

Kept separate from seed.py so both the CLI seeder and the app's startup
auto-seed can use it without create_app() recursion.
"""

from extensions import db
from models import User, Patient, ROLE_ADMIN, ROLE_USER, ROLE_VIEWER
from patient_seed import generate_patients

DEMO_USERS = [
    # username,        email,                             password,          role
    ("Abdul Rehman", "abdulrehmanarainmanni@gmail.com", "AbdulRehman2711", ROLE_ADMIN),
    ("user",         "user@secureaccess.pro",           "User@123",        ROLE_USER),
    ("viewer",       "viewer@secureaccess.pro",         "Viewer@123",      ROLE_VIEWER),
]


def seed_demo(app, reset=False):
    """Create demo accounts + patient records. Returns list of (user, password)
    for accounts created in this call."""
    with app.app_context():
        if reset:
            db.drop_all()
            db.create_all()

        created = []  # list of (username, password) created in this call
        for username, email, password, role in DEMO_USERS:
            if User.query.filter_by(username=username).first():
                continue
            u = User(username=username, email=email, role=role,
                     totp_secret=User.new_totp_secret())
            u.set_password(password)
            db.session.add(u)
            created.append((username, password))
        db.session.commit()

        if Patient.query.count() == 0:
            for p in generate_patients():
                db.session.add(Patient(**p))
            db.session.commit()

        return created


def is_empty(app):
    with app.app_context():
        try:
            return User.query.count() == 0
        except Exception:
            return True
