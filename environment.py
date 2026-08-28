"""Runtime configuration for the focused email/phone issuer."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot load configuration file {path.name}") from exc

    if not isinstance(value, dict):
        raise TypeError(f"Configuration file {path.name} must contain an object")
    return value


def _value(env_name: str, source: dict, key: str, default: str = "") -> str:
    value = os.getenv(env_name, source.get(key, default))
    return str(value).strip()


@dataclass(frozen=True)
class Settings:
    environment: str
    host: str
    port: int
    secret_key: str
    secure_cookies: bool
    hub_url: str
    hub_api_key: str
    hub_request_timeout: float
    issuance_expires_in: int
    event_poll_interval: float
    email_hub_issuer: str
    email_credential_configuration_id: str
    email_claim: str
    phone_hub_issuer: str
    phone_credential_configuration_id: str
    phone_claim: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_from: str
    smtp_starttls: bool
    sms_token: str
    counter_path: Path
    counter_api_key: str
    slack_url: str


def load_settings(environment: str | None = None) -> Settings:
    """Load secrets locally without exposing them at module import time."""

    selected_environment = environment or os.getenv("MYENV", "local")
    if selected_environment not in {"local", "aws"}:
        raise RuntimeError("MYENV must be either 'local' or 'aws'")

    passwords = _load_json(BASE_DIR / "passwords.json")
    keys = _load_json(BASE_DIR / "keys.json")
    secret_key = _value("ISSUER_SECRET_KEY", passwords, "password")
    hub_api_key = _value("OPENID4VC_HUB_API_KEY", keys, "openid4vc_hub_api_key")
    if not secret_key:
        raise RuntimeError(
            "ISSUER_SECRET_KEY or passwords.json['password'] is required"
        )
    if not hub_api_key:
        raise RuntimeError(
            "OPENID4VC_HUB_API_KEY or keys.json['openid4vc_hub_api_key'] is required"
        )

    default_host = "0.0.0.0" if selected_environment == "aws" else "127.0.0.1"
    return Settings(
        environment=selected_environment,
        host=os.getenv("ISSUER_HOST", default_host),
        port=int(os.getenv("ISSUER_PORT", "5100")),
        secret_key=secret_key,
        secure_cookies=selected_environment == "aws",
        hub_url=os.getenv("OPENID4VC_HUB_URL", "https://openid4vc-hub.com").rstrip("/"),
        hub_api_key=hub_api_key,
        hub_request_timeout=float(os.getenv("HUB_REQUEST_TIMEOUT", "10")),
        issuance_expires_in=int(os.getenv("ISSUANCE_EXPIRES_IN", "600")),
        event_poll_interval=float(os.getenv("EVENT_POLL_INTERVAL", "1.5")),
        email_hub_issuer=os.getenv("EMAIL_HUB_ISSUER", "core-email-proof-issuer"),
        email_credential_configuration_id=os.getenv(
            "EMAIL_CREDENTIAL_CONFIGURATION_ID", "email_proof_sd_jwt"
        ),
        email_claim=os.getenv("EMAIL_CREDENTIAL_CLAIM", "email"),
        phone_hub_issuer=os.getenv("PHONE_HUB_ISSUER", "core-phone-proof-issuer"),
        phone_credential_configuration_id=os.getenv(
            "PHONE_CREDENTIAL_CONFIGURATION_ID", "phone_sd_jwt"
        ),
        phone_claim=os.getenv("PHONE_CREDENTIAL_CLAIM", "phone_number"),
        smtp_host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_username=os.getenv("SMTP_USERNAME", "relay@talao.io"),
        smtp_password=_value("SMTP_PASSWORD", passwords, "smtp_password"),
        smtp_from=os.getenv("SMTP_FROM", "Talao <relay@talao.io>"),
        smtp_starttls=os.getenv("SMTP_STARTTLS", "1") != "0",
        sms_token=_value("SMS_API_TOKEN", passwords, "sms_token"),
        counter_path=Path(
            os.getenv("COUNTER_PATH", str(BASE_DIR / "counter.json"))
        ).resolve(),
        counter_api_key=os.getenv("COUNTER_API_KEY", ""),
        slack_url=_value("COUNTER_SLACK_URL", passwords, "slack_url"),
    )
