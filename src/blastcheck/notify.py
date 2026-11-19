"""Optional delivery of a short notice to Slack or email. Failures are reported, never fatal."""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage

from . import http


def notice(headline_text: str, package: str, reply_text: str, issue_url: str) -> str:
    link = f"\nDetails: {issue_url}" if issue_url else ""
    return f"blastcheck: {package}\n{headline_text}\n\n{reply_text}{link}"


def send_slack(webhook_url: str, text: str) -> None:
    http.request("POST", webhook_url, payload={"text": text}, attempts=2)


def send_email(env: dict[str, str], subject: str, text: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = env["BLASTCHECK_MAIL_FROM"]
    message["To"] = env["BLASTCHECK_MAIL_TO"]
    message.set_content(text)
    host, port = env["BLASTCHECK_SMTP_HOST"], int(env.get("BLASTCHECK_SMTP_PORT") or "587")
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        if env.get("BLASTCHECK_SMTP_USER"):
            smtp.login(env["BLASTCHECK_SMTP_USER"], env.get("BLASTCHECK_SMTP_PASSWORD", ""))
        smtp.send_message(message)


def deliver(text: str, subject: str, env: dict[str, str] | None = None) -> list[str]:
    """Send to every configured channel. Returns one line per channel describing what happened."""
    env = dict(os.environ) if env is None else env
    outcomes: list[str] = []
    if env.get("BLASTCHECK_SLACK_WEBHOOK"):
        try:
            send_slack(env["BLASTCHECK_SLACK_WEBHOOK"], text)
            outcomes.append("slack: sent")
        except http.HttpError as exc:
            outcomes.append(f"slack: FAILED (HTTP {exc.status})")
    if env.get("BLASTCHECK_SMTP_HOST"):
        try:
            send_email(env, subject, text)
            outcomes.append("email: sent")
        except (KeyError, ValueError, OSError, smtplib.SMTPException) as exc:
            outcomes.append(f"email: FAILED ({type(exc).__name__}: {exc})")
    return outcomes
