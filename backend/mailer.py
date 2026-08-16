"""
Email delivery for SecureAccess Pro.

Sends login OTP codes, a welcome message on sign-up, and password-reset codes to
users' registered addresses over SMTP (Gmail-compatible). If SMTP credentials
are not configured, runs in DEV MODE: the content is printed to the server
console and (for codes) returned to the caller so the system stays demoable.
"""

import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app


def _smtp_configured():
    cfg = current_app.config
    return bool(cfg.get("SMTP_USER")) and bool(cfg.get("SMTP_PASSWORD"))


def _send(subject, body, to_email):
    """Send one email. Returns True if actually delivered via SMTP, else False
    (dev mode: printed to console)."""
    cfg = current_app.config
    if not _smtp_configured() or not to_email:
        print(f"[DEV EMAIL] to={to_email} | {subject}\n{body}\n")
        return False
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
    return True


def send_otp_email(to_email, code):
    """Deliver a login OTP. Returns (delivered, dev_code)."""
    mins = current_app.config["OTP_EXPIRES_MINUTES"]
    body = (
        f"Your one-time login code is: {code}\n\n"
        f"It expires in {mins} minutes.\n"
        "If you did not request this, please ignore this email.\n\n"
        "— SecureAccess Pro"
    )
    delivered = _send("Your SecureAccess Pro login code", body, to_email)
    return delivered, (None if delivered else code)


def send_reset_email(to_email, code):
    """Deliver a password-reset code. Returns (delivered, dev_code)."""
    mins = current_app.config.get("RESET_EXPIRES_MINUTES", 15)
    body = (
        "We received a request to reset your SecureAccess Pro password.\n\n"
        f"Your password reset code is: {code}\n\n"
        f"It expires in {mins} minutes. Enter it on the reset screen to set a "
        "new password.\n"
        "If you did not request this, you can safely ignore this email — your "
        "password will remain unchanged.\n\n"
        "— SecureAccess Pro Security Team"
    )
    delivered = _send("Your SecureAccess Pro password reset code", body, to_email)
    return delivered, (None if delivered else code)


def send_welcome_email(to_email, username, role):
    """Send a professional welcome email when an account is created."""
    body = (
        f"Dear {username},\n\n"
        "Welcome to SecureAccess Pro — your Zero Trust Network Access Control "
        "System.\n\n"
        f"Your account has been created successfully with the role: {role}.\n\n"
        "For your security, every sign-in is protected by multi-factor "
        "authentication (a one-time code sent to this email), and all activity "
        "is continuously monitored under our Zero Trust policy.\n\n"
        "Getting started:\n"
        "  1. Go to the login page and enter your username and password.\n"
        "  2. Click 'Email me a code' to receive your one-time login code.\n"
        "  3. Enter the code to securely access the resources permitted for "
        "your role.\n\n"
        "If you did not create this account, please contact your administrator "
        "immediately.\n\n"
        "Thank you for choosing SecureAccess Pro.\n\n"
        "Best regards,\n"
        "The SecureAccess Pro Team"
    )
    return _send("Welcome to SecureAccess Pro", body, to_email)
