#!/usr/bin/env python3
"""
SecureAccess Pro - one-command launcher.

Run everything with a single command:

    python run.py

It will:
  1. Seed the database on first run (demo accounts + 55 patients).
  2. Start the backend API in the background.
  3. Open a small launcher window with buttons to open the User App and the
     Admin Security Dashboard (each in its own window).

No need to run separate commands or terminals.
"""

import os
import sys
import time
import threading
import subprocess
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(ROOT, "backend")
CLIENT = os.path.join(ROOT, "client")
sys.path.insert(0, BACKEND)

API_URL = "http://127.0.0.1:5000"


def seed_if_needed():
    from app import app
    from models import User
    with app.app_context():
        try:
            empty = User.query.count() == 0
        except Exception:
            empty = True
    if empty:
        print("First run: seeding database (demo accounts + patients)...")
        from seed import seed
        seed(reset=False)
    else:
        print("Database already set up.")


def run_backend():
    from app import app
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False, threaded=True)


def wait_for_server(timeout=20):
    for _ in range(timeout * 2):
        try:
            urllib.request.urlopen(API_URL + "/", timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def open_gui(script):
    subprocess.Popen([sys.executable, os.path.join(CLIENT, script)], cwd=CLIENT)


def launcher():
    import tkinter as tk

    BG, CARD, TEAL, MINT, TEXT, MUTED = "#0f2027", "#16323a", "#028090", "#02c39a", "#eaf4f4", "#9db4b8"
    root = tk.Tk()
    root.title("SecureAccess Pro — Launcher")
    root.geometry("560x520")
    root.configure(bg=BG)

    tk.Label(root, text="\U0001F510  SecureAccess Pro", font=("Segoe UI", 22, "bold"),
             bg=BG, fg=TEXT).pack(pady=(26, 2))
    tk.Label(root, text="Backend is running at " + API_URL, font=("Segoe UI", 10),
             bg=BG, fg=MINT).pack()

    card = tk.Frame(root, bg=CARD, padx=30, pady=24)
    card.pack(pady=22, fill="x", padx=30)
    tk.Label(card, text="Open an application", font=("Segoe UI", 13, "bold"),
             bg=CARD, fg=TEXT).pack(anchor="w", pady=(0, 12))
    tk.Button(card, text="\U0001F464  User Application", font=("Segoe UI", 12, "bold"),
              bg=TEAL, fg="white", activebackground=MINT, relief="flat", padx=10, pady=10,
              cursor="hand2", command=lambda: open_gui("user_app.py")).pack(fill="x", pady=6)
    tk.Button(card, text="\U0001F6E1  Admin Security Dashboard", font=("Segoe UI", 12, "bold"),
              bg=TEAL, fg="white", activebackground=MINT, relief="flat", padx=10, pady=10,
              cursor="hand2", command=lambda: open_gui("admin_dashboard.py")).pack(fill="x", pady=6)

    tk.Label(root, text="Sign in with your account, or create a new one.\n"
                        "MFA: click 'Email me a code' on the login screen.",
             font=("Segoe UI", 9), bg=BG, fg=MUTED, justify="center").pack(pady=(14, 0))

    root.mainloop()


def main():
    print("=" * 60)
    print(" SecureAccess Pro — starting up")
    print("=" * 60)
    seed_if_needed()

    threading.Thread(target=run_backend, daemon=True).start()
    print("Starting backend ...")
    if not wait_for_server():
        print("ERROR: backend did not start. Check that port 5000 is free.")
        sys.exit(1)
    print("Backend ready at " + API_URL)
    print("Opening launcher window ...")
    launcher()


if __name__ == "__main__":
    main()
