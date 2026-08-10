"""
Demo helper: print the current TOTP code for a user (so the system can be
demonstrated without a phone / authenticator app).

Usage:
    python show_code.py admin
"""

import sys

from app import create_app
from models import User


def main():
    if len(sys.argv) < 2:
        print("Usage: python show_code.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    app = create_app()
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"No such user: {username!r}. Run 'python seed.py' first.")
            sys.exit(1)
        code = user.current_totp(interval=app.config["TOTP_INTERVAL"])
        print(f"Current TOTP for {username}: {code}  (valid ~30s)")


if __name__ == "__main__":
    main()
