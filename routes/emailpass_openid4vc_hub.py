from __future__ import annotations

import base64
import io
import json
import logging
import secrets
import time
import uuid
from pathlib import Path

import qrcode
import requests
from flask import (
    Response,
    jsonify,
    render_template,
    request,
    session,
    flash,
)
from flask_babel import _
from qrcode.image.svg import SvgPathImage

from components import message


logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# openid4vc-hub configuration
# ---------------------------------------------------------------------------

OPENID4VC_HUB_URL = "https://openid4vc-hub.com"
OPENID4VC_HUB_ISSUER = "core-email-proof-issuer"
OPENID4VC_HUB_CREDENTIAL_CONFIGURATION_ID = "email_proof_sd_jwt"

REQUEST_TIMEOUT = 10
ISSUANCE_EXPIRES_IN = 600
TX_CODE_LENGTH = 4
EMAIL_CODE_TEMPLATE = "code_auth_en"

# SSE polling cadence from this application to openid4vc-hub.
EVENT_POLL_INTERVAL = 1.5


def _load_hub_api_key() -> str:
    keys_path = Path(__file__).resolve().parent.parent / "keys.json"

    try:
        data = json.loads(keys_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot load {keys_path}: {exc}") from exc

    api_key = str(data.get("openid4vc_hub_api_key", "")).strip()
    if not api_key:
        raise RuntimeError(
            "keys.json must contain 'openid4vc_hub_api_key'"
        )
    return api_key


OPENID4VC_HUB_API_KEY = _load_hub_api_key()


# ---------------------------------------------------------------------------
# Flask registration
# ---------------------------------------------------------------------------

def init_app(app, red, mode):
    """
    Register the standalone Proof of Email flow using openid4vc-hub.

    `red` is kept only for compatibility with the existing module loader.
    """
    del red

    app.add_url_rule(
        "/emailproof-hub",
        view_func=emailpass_hub_start,
        methods=["GET", "POST"],
        defaults={"mode": mode},
    )
    app.add_url_rule(
        "/emailpass-hub",
        view_func=emailpass_hub_start,
        methods=["GET", "POST"],
        defaults={"mode": mode},
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hub_headers() -> dict[str, str]:
    return {
        "X-API-Key": OPENID4VC_HUB_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _response_json(response: requests.Response) -> dict:
    try:
        payload = response.json()
    except ValueError:
        return {
            "error": "invalid_hub_response",
            "error_description": response.text[:1000],
        }

    if isinstance(payload, dict):
        return payload

    return {
        "error": "invalid_hub_response",
        "error_description": "Hub response is not a JSON object.",
    }


def _generate_tx_code() -> str:
    lower = 10 ** (TX_CODE_LENGTH - 1)
    upper = (10 ** TX_CODE_LENGTH) - lower
    return str(lower + secrets.randbelow(upper))


def _qr_svg_data_uri(content: str) -> str:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(content)
    qr.make(fit=True)

    image = qr.make_image(image_factory=SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)

    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def _send_tx_code(email: str, tx_code: str, mode) -> None:
    subject = _("Your Proof of Email wallet verification code")
    message.messageHTML(
        subject,
        email,
        EMAIL_CODE_TEMPLATE,
        {"code": tx_code},
        mode,
    )


def _get_issuance_status(issuance_id: str) -> tuple[dict, int]:
    try:
        response = requests.get(
            f"{OPENID4VC_HUB_URL}/api/v1/issuances/{issuance_id}",
            headers=_hub_headers(),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        logging.warning("Cannot poll openid4vc-hub: %s", exc)
        return (
            {
                "status": "pending",
                "error": "hub_temporarily_unavailable",
                "error_description": "Temporary connection issue.",
            },
            502,
        )

    return _response_json(response), response.status_code


# ---------------------------------------------------------------------------
# Proof of Email flow
# ---------------------------------------------------------------------------

def emailpass_hub_start(mode):
    """
    GET:
        Display the dedicated Proof of Email form.

    POST:
        - validate email;
        - generate and send the OIDC4VCI transaction code by email;
        - create an issuance in openid4vc-hub;
        - render the QR/deep-link page.

    The transaction code is entered only in the wallet.
    """

    if request.method == "GET":
        return render_template("emailpass/emailpass_hub.html")

    email = request.form.get("email", "").strip().lower()
    if not email or "@" not in email:
        flash(_("Invalid email address."), "danger")
        return render_template(
            "emailpass/emailpass_hub.html",
            email=email,
        )

    tx_code = _generate_tx_code()

    # Send the code before creating the offer. If email delivery fails,
    # avoid creating an issuance that the user cannot complete.
    try:
        _send_tx_code(email, tx_code, mode)
        logging.info("Proof of Email transaction code sent to %s", email)
    except Exception:
        logging.exception("Proof of Email transaction-code email failed")
        flash(_("Email failed. Please try again."), "danger")
        return render_template(
            "emailpass/emailpass_hub.html",
            email=email,
        )

    payload = {
        "issuer": OPENID4VC_HUB_ISSUER,
        "credentials": [
            {
                "credential_configuration_id": (
                    OPENID4VC_HUB_CREDENTIAL_CONFIGURATION_ID
                ),
                "claims": {
                    "email": email,
                },
            }
        ],
        "reference": f"emailpass-{uuid.uuid4()}",
        "tx_code": {
            "value": tx_code,
            "input_mode": "numeric",
            "description": (
                "Enter the verification code sent to your email address."
            ),
        },
        "expires_in": ISSUANCE_EXPIRES_IN,
    }

    try:
        response = requests.post(
            f"{OPENID4VC_HUB_URL}/api/v1/issuances",
            headers=_hub_headers(),
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        logging.exception("Cannot reach openid4vc-hub")
        flash(
            _("Credential issuer is temporarily unavailable."),
            "danger",
        )
        return render_template(
            "emailpass/emailpass_hub.html",
            email=email,
        )

    response_data = _response_json(response)

    if response.status_code not in (200, 201):
        logging.error(
            "Hub issuance creation failed HTTP %s: %s",
            response.status_code,
            response_data,
        )
        flash(
            response_data.get(
                "error_description",
                _("Credential issuance failed."),
            ),
            "danger",
        )
        return render_template(
            "emailpass/emailpass_hub.html",
            email=email,
        )

    issuance_id = response_data.get("issuance_id")
    qr_code_content = response_data.get("qr_code_content")

    if not issuance_id or not qr_code_content:
        logging.error("Incomplete Hub response: %s", response_data)
        flash(
            _("Credential issuer returned an incomplete response."),
            "danger",
        )
        return render_template(
            "emailpass/emailpass_hub.html",
            email=email,
        )

    session["emailpass_hub_issuance_id"] = issuance_id
    session["emailpass_hub_email"] = email

    return render_template(
        "emailpass/emailpass_hub_qr.html",
        issuance_id=issuance_id,
        email=email,
        qr_code_content=qr_code_content,
        qr_image=_qr_svg_data_uri(qr_code_content),
        expires_in=ISSUANCE_EXPIRES_IN,
    )


# ---------------------------------------------------------------------------
# Status / SSE
# ---------------------------------------------------------------------------

def emailpass_hub_status(issuance_id: str):
    """
    Optional JSON status endpoint. Kept for diagnostics and fallback.
    """
    if issuance_id != session.get("emailpass_hub_issuance_id"):
        return jsonify(
            {
                "error": "forbidden",
                "error_description": "Unknown issuance for this session.",
            }
        ), 403

    payload, status_code = _get_issuance_status(issuance_id)
    return jsonify(payload), status_code


def emailpass_hub_events(issuance_id: str):
    """
    SSE endpoint inspired by the original emailpass event stream.

    The browser opens one EventSource connection. This backend polls
    openid4vc-hub and emits status events until a terminal state is reached.
    """

    if issuance_id != session.get("emailpass_hub_issuance_id"):
        return jsonify(
            {
                "error": "forbidden",
                "error_description": "Unknown issuance for this session.",
            }
        ), 403

    def event_stream():
        last_serialized = None

        while True:
            payload, status_code = _get_issuance_status(issuance_id)
            status = payload.get("status", "pending")

            event_payload = {
                "status": status,
                "http_status": status_code,
            }

            if payload.get("error"):
                event_payload["error"] = payload["error"]

            if payload.get("error_description"):
                event_payload["error_description"] = payload[
                    "error_description"
                ]

            serialized = json.dumps(event_payload, ensure_ascii=False)

            # Do not flood the browser with identical updates.
            if serialized != last_serialized:
                yield f"data: {serialized}\n\n"
                last_serialized = serialized

            if status in {"completed", "failed", "expired"}:
                # Do not clear the ownership marker here. The generator runs
                # after the request context has started and must remain simple.
                break

            time.sleep(EVENT_POLL_INTERVAL)

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-store",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }

    return Response(event_stream(), headers=headers)