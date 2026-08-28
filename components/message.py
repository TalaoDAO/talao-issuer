"""Email delivery for the Proof of Email transaction code."""

import html
import smtplib
from email.message import EmailMessage


def send_verification_code(email: str, code: str, settings) -> None:
    if not settings.smtp_password:
        raise RuntimeError("SMTP_PASSWORD is not configured")

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = email
    message["Subject"] = "Your Proof of Email verification code"
    message.set_content(f"Your verification code is: {code}")
    message.add_alternative(
        f"""
        <!doctype html>
        <html lang="en">
          <body style="font-family:Arial,sans-serif;text-align:center;padding:32px">
            <h1 style="font-size:24px">Your verification code</h1>
            <p style="font-size:42px;font-weight:700;letter-spacing:6px">{html.escape(code)}</p>
            <p>Enter this code only in your wallet.</p>
          </body>
        </html>
        """,
        subtype="html",
    )

    with smtplib.SMTP(
        settings.smtp_host,
        settings.smtp_port,
        timeout=settings.hub_request_timeout,
    ) as smtp:
        if settings.smtp_starttls:
            smtp.starttls()
        smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)
