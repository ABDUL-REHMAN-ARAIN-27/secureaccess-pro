"""
Email delivery for one-time passcodes (OTP).

Sends the login OTP to a user's registered email over SMTP (Gmail-compatible).
If SMTP credentials are not configured, runs in DEV MODE: the code is printed
to the server console and returned to the caller so the system stays demoable
without an email account.
"""

import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app


def _smtp_configured():
    cfg = current_app.config
    return bool(cfg.get("SMTP_USER")) and bool(cfg.get("SMTP_PASSWORD"))


def send_otp_email(to_email, code):
    """
    Deliver an OTP code.

    Returns (delivered, dev_code):
      - delivered: True if actually emailed via SMTP, False if dev-mode/console.
      - dev_code : the code when running in dev mode (so the GUI can show it),
                   otherwise None.
    """
    cfg = current_app.config
    subject = "Your SecureAccess Pro login code"
    body = (
        f"Your one-time login code is: {code}\n\n"
        f"It expires in {cfg['OTP_EXPIRES_MINUTES']} minutes.\n"
        "If you did not request this, ignore this email.\n\n"
        "— SecureAccess Pro"
    )

    if not _smtp_configured():
        # DEV MODE — no real email account configured.
        print(f"[DEV OTP] code for {to_email}: {code}")
        return False, code

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = to_email
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as server:
        server.starttls(context=context)
        server.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
        server.send_message(msg)
    return True, None
