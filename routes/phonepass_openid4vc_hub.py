"""Proof of Phone issuance through openid4vc-hub."""

from __future__ import annotations

import re
import secrets
import uuid

from flask import current_app, flash, render_template, request, session, url_for

from components import sms
from components.openid4vc_hub import HubError, qr_svg_data_uri
from routes.hub_flow import issuance_events, issuance_status

SESSION_KEY = "phonepass_hub_issuance_id"
PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")
TX_CODE_LENGTH = 4


def init_app(app):
    app.add_url_rule(
        "/phoneproof",
        endpoint="phone_proof_start",
        view_func=phone_proof_start,
        methods=["GET", "POST"],
    )
    for index, alias in enumerate(("/phonepass-hub", "/phonepass", "/phoneproof-hub")):
        app.add_url_rule(
            alias,
            endpoint=f"phone_proof_alias_{index}",
            view_func=phone_proof_start,
            methods=["GET", "POST"],
        )
    app.add_url_rule(
        "/phoneproof/status/<issuance_id>",
        endpoint="phone_proof_status",
        view_func=phone_proof_status,
        methods=["GET"],
    )
    app.add_url_rule(
        "/phonepass-hub/status/<issuance_id>",
        endpoint="phone_proof_status",
        view_func=phone_proof_status,
        methods=["GET"],
    )
    app.add_url_rule(
        "/phoneproof/events/<issuance_id>",
        endpoint="phone_proof_events",
        view_func=phone_proof_events,
        methods=["GET"],
    )
    app.add_url_rule(
        "/phonepass-hub/events/<issuance_id>",
        endpoint="phone_proof_events",
        view_func=phone_proof_events,
        methods=["GET"],
    )


def _generate_tx_code() -> str:
    lower = 10 ** (TX_CODE_LENGTH - 1)
    return str(lower + secrets.randbelow(9 * lower))


def normalize_phone_number(value: str) -> str | None:
    compact = re.sub(r"[\s().-]", "", value.strip())
    if compact.startswith("00"):
        compact = f"+{compact[2:]}"
    elif not compact.startswith("+") and compact.isdigit():
        compact = f"+{compact}"
    return compact if PHONE_PATTERN.fullmatch(compact) else None


def _masked_phone(phone_number: str) -> str:
    return f"{phone_number[:4]}{'*' * max(3, len(phone_number) - 7)}{phone_number[-3:]}"


def phone_proof_start():
    settings = current_app.extensions["issuer_settings"]
    if request.method == "GET":
        return phone_proof_start_form("")

    raw_phone = request.form.get("phone", "")
    phone_number = normalize_phone_number(raw_phone)
    if phone_number is None:
        flash(
            "Enter a valid international phone number, for example +33612345678.",
            "danger",
        )
        return phone_proof_start_form(raw_phone), 400

    tx_code = _generate_tx_code()
    try:
        sent = sms.send_verification_code(phone_number, tx_code, settings)
    except Exception:
        current_app.logger.exception("Proof of Phone code delivery failed")
        sent = False
    if not sent:
        flash("The verification SMS could not be sent. Please try again.", "danger")
        return phone_proof_start_form(raw_phone), 502

    payload = {
        "issuer": settings.phone_hub_issuer,
        "credentials": [
            {
                "credential_configuration_id": (
                    settings.phone_credential_configuration_id
                ),
                "claims": {settings.phone_claim: phone_number},
            }
        ],
        "reference": f"phonepass-{uuid.uuid4()}",
        "tx_code": {
            "value": tx_code,
            "input_mode": "numeric",
            "description": "Enter the verification code sent by SMS.",
        },
        "expires_in": settings.issuance_expires_in,
    }
    try:
        response = current_app.extensions["hub_client"].create_issuance(payload)
    except HubError as exc:
        current_app.logger.warning("Proof of Phone hub creation failed: %s", exc)
        flash("The issuance service is temporarily unavailable.", "danger")
        return phone_proof_start_form(raw_phone), 502

    issuance_id = response.get("issuance_id")
    qr_content = response.get("qr_code_content")
    if not isinstance(issuance_id, str) or not isinstance(qr_content, str):
        current_app.logger.error("Proof of Phone hub response is incomplete")
        flash("The issuance service returned an incomplete response.", "danger")
        return phone_proof_start_form(raw_phone), 502

    session[SESSION_KEY] = issuance_id
    return render_template(
        "proof_offer.html",
        proof_name="Proof of Phone",
        masked_subject=_masked_phone(phone_number),
        qr_code_content=qr_content,
        qr_image=qr_svg_data_uri(qr_content),
        events_url=url_for("phone_proof_events", issuance_id=issuance_id),
        restart_url=url_for("phone_proof_start"),
        expires_in=settings.issuance_expires_in,
    )


def phone_proof_start_form(value: str):
    return render_template(
        "proof_form.html",
        proof_name="Proof of Phone",
        icon="+",
        description=(
            "Enter your phone number in international format. The verification "
            "code will be entered directly in your wallet."
        ),
        field_name="phone",
        field_label="Phone number",
        input_type="tel",
        autocomplete="tel",
        value=value,
        submit_url=url_for("phone_proof_start"),
    )


def phone_proof_status(issuance_id: str):
    return issuance_status(SESSION_KEY, "phonepass", issuance_id)


def phone_proof_events(issuance_id: str):
    return issuance_events(SESSION_KEY, "phonepass", issuance_id)
