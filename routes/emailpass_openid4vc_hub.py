"""Proof of Email issuance through openid4vc-hub."""

from __future__ import annotations

import re
import secrets
import uuid

from flask import current_app, flash, render_template, request, session, url_for

from components import message
from components.openid4vc_hub import HubError, qr_svg_data_uri
from routes.hub_flow import issuance_events, issuance_status

SESSION_KEY = "emailpass_hub_issuance_id"
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
TX_CODE_LENGTH = 4


def init_app(app):
    app.add_url_rule(
        "/emailproof-hub",
        endpoint="emailpass_hub_start",
        view_func=emailpass_hub_start,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/emailpass-hub",
        endpoint="emailpass_hub_start",
        view_func=emailpass_hub_start,
        methods=["GET", "POST"],
    )
    for index, alias in enumerate(("/emailproof", "/emailpass")):
        app.add_url_rule(
            alias,
            endpoint=f"email_proof_alias_{index}",
            view_func=emailpass_hub_start,
            methods=["GET", "POST"],
        )
    app.add_url_rule(
        "/emailpass-hub/status/<issuance_id>",
        view_func=emailpass_hub_status,
        methods=["GET"],
    )
    app.add_url_rule(
        "/emailpass-hub/events/<issuance_id>",
        view_func=emailpass_hub_events,
        methods=["GET"],
    )


def _generate_tx_code() -> str:
    lower = 10 ** (TX_CODE_LENGTH - 1)
    return str(lower + secrets.randbelow(9 * lower))


def _masked_email(email: str) -> str:
    local, domain = email.split("@", 1)
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(1, len(local) - len(visible))}@{domain}"


def emailpass_hub_start():
    settings = current_app.extensions["issuer_settings"]
    if request.method == "GET":
        return emailpass_hub_start_form("")

    email = request.form.get("email", "").strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        flash("Invalid email address.", "danger")
        return emailpass_hub_start_form(email), 400

    tx_code = _generate_tx_code()
    try:
        message.send_verification_code(email, tx_code, settings)
    except Exception:
        current_app.logger.exception("Proof of Email code delivery failed")
        flash("The verification email could not be sent. Please try again.", "danger")
        return emailpass_hub_start_form(email), 502

    payload = {
        "issuer": settings.email_hub_issuer,
        "credentials": [
            {
                "credential_configuration_id": (
                    settings.email_credential_configuration_id
                ),
                "claims": {settings.email_claim: email},
            }
        ],
        "reference": f"emailpass-{uuid.uuid4()}",
        "tx_code": {
            "value": tx_code,
            "input_mode": "numeric",
            "description": "Enter the verification code sent by email.",
        },
        "expires_in": settings.issuance_expires_in,
    }
    try:
        response = current_app.extensions["hub_client"].create_issuance(payload)
    except HubError as exc:
        current_app.logger.warning("Proof of Email hub creation failed: %s", exc)
        flash("The issuance service is temporarily unavailable.", "danger")
        return emailpass_hub_start_form(email), 502

    issuance_id = response.get("issuance_id")
    qr_content = response.get("qr_code_content")
    if not isinstance(issuance_id, str) or not isinstance(qr_content, str):
        current_app.logger.error("Proof of Email hub response is incomplete")
        flash("The issuance service returned an incomplete response.", "danger")
        return emailpass_hub_start_form(email), 502

    session[SESSION_KEY] = issuance_id
    return render_template(
        "proof_offer.html",
        proof_name="Proof of Email",
        masked_subject=_masked_email(email),
        qr_code_content=qr_content,
        qr_image=qr_svg_data_uri(qr_content),
        events_url=url_for("emailpass_hub_events", issuance_id=issuance_id),
        restart_url="/emailpass-hub",
        expires_in=settings.issuance_expires_in,
    )


def emailpass_hub_start_form(email: str):
    return render_template(
        "proof_form.html",
        proof_name="Proof of Email",
        icon="@",
        description=(
            "Enter your email address. The verification code will be entered "
            "directly in your wallet."
        ),
        field_name="email",
        field_label="Email address",
        input_type="email",
        autocomplete="email",
        value=email,
        submit_url="/emailpass-hub",
    )


def emailpass_hub_status(issuance_id: str):
    return issuance_status(SESSION_KEY, "emailpass", issuance_id)


def emailpass_hub_events(issuance_id: str):
    return issuance_events(SESSION_KEY, "emailpass", issuance_id)
