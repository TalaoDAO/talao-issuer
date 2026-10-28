"""Proof of Email issuance through openid4vc-hub."""

from __future__ import annotations

import re
import hashlib
import hmac
import time
import secrets
import uuid

from flask import current_app, flash, render_template, request, session, url_for, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from components.wallet_delivery import deliver_offer, WalletDeliveryError

from components import message
from components.openid4vc_hub import HubError, qr_svg_data_uri
from routes.hub_flow import issuance_events, issuance_status, verify_contact_on_site

SESSION_KEY = "emailpass_hub_issuance_id"
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
CHALLENGE_KEY = "emailpass_verification"


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
    app.add_url_rule(
        "/emailpass/altme",
        endpoint="emailpass_altme_start",
        view_func=emailpass_altme_start,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
            "/emailpass/generic",
            endpoint="emailpass_generic_start",
            view_func=emailpass_generic_start,
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

    app.add_url_rule(
        "/emailpass-hub/send-offer",
        endpoint="emailpass_hub_send_offer",
        view_func=emailpass_hub_send_offer,
        methods=["POST"],
    )


def _masked_email(email: str) -> str:
    local, domain = email.split("@", 1)
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(1, len(local) - len(visible))}@{domain}"


def emailpass_hub_start():
    settings = current_app.extensions["issuer_settings"]
    return _emailpass_start(
        settings.email_hub_issuer,
        "/emailpass-hub",
    )


def emailpass_altme_start():
    settings = current_app.extensions["issuer_settings"]
    return _emailpass_start(
        settings.altme_email_hub_issuer,
        url_for("emailpass_altme_start"),
    )


def emailpass_generic_start():
    settings = current_app.extensions["issuer_settings"]
    return _emailpass_start(
        settings.generic_email_hub_issuer,
        url_for("emailpass_generic_start"),
    )


def _emailpass_start(hub_issuer: str, submit_url: str):
    settings = current_app.extensions["issuer_settings"]
    if request.method == "GET":
        return emailpass_hub_start_form("", submit_url)

    email, response = verify_contact_on_site(
        store_key="email_verification_store", session_key=CHALLENGE_KEY,
        issuer=hub_issuer, submit_url=submit_url, field_name="email",
        normalize=lambda value: value.strip().lower() if EMAIL_PATTERN.fullmatch(value.strip()) else None,
        mask=_masked_email, send_code=message.send_verification_code,
        start_form=lambda: emailpass_hub_start_form("", submit_url),
        invalid_message="Invalid email address.",
        delivery_error="The verification email could not be sent. Please try again.",
        proof_name="Proof of Email", contact_name="email", icon="@",
    )
    if response is not None:
        return response

    payload = {
        "issuer": hub_issuer,
        "credentials": [
            {
                "credential_configuration_id": (
                    settings.email_credential_configuration_id
                ),
                "claims": {settings.email_claim: email},
            }
        ],
        "reference": f"emailpass-{uuid.uuid4()}",
        "expires_in": min(settings.issuance_expires_in, 300),
    }
    try:
        response = current_app.extensions["hub_client"].create_issuance(payload)
    except HubError as exc:
        current_app.logger.warning("Proof of Email hub creation failed: %s", exc)
        flash("The issuance service is temporarily unavailable.", "danger")
        return emailpass_hub_start_form("", submit_url), 502

    issuance_id = response.get("issuance_id")
    qr_content = response.get("qr_code_content")
    if not isinstance(issuance_id, str) or not isinstance(qr_content, str):
        current_app.logger.error("Proof of Email hub response is incomplete")
        flash("The issuance service returned an incomplete response.", "danger")
        return emailpass_hub_start_form("", submit_url), 502

    session[SESSION_KEY] = issuance_id
    delivery_nonce = secrets.token_urlsafe(32)
    session['emailpass_delivery'] = {'nonce': delivery_nonce,
        'expires_at': time.time() + min(settings.issuance_expires_in, 300)}
    delivery_context = _delivery_serializer().dumps({
        'issuance_id': issuance_id, 'offer': qr_content, 'nonce': delivery_nonce})
    return render_template(
        "proof_offer.html",
        proof_name="Proof of Email",
        desktop_delivery=True,
        delivery_context=delivery_context,
        delivery_url=url_for('emailpass_hub_send_offer'),
        masked_subject=_masked_email(email),
        qr_code_content=qr_content,
        qr_image=qr_svg_data_uri(qr_content),
        events_url=url_for("emailpass_hub_events", issuance_id=issuance_id),
        restart_url=submit_url,
        expires_in=min(settings.issuance_expires_in, 300),
        verified_contact="email",
    )


def emailpass_hub_start_form(email: str, submit_url: str = "/emailpass-hub"):
    return render_template(
        "proof_form.html",
        proof_name="Proof of Email",
        icon="@",
        description=(
            "Enter your email address. Then enter the six-digit code on this site "
            "to verify it before opening your wallet."
        ),
        contact_name="email",
        field_name="email",
        field_label="Email address",
        input_type="email",
        autocomplete="email",
        value=email,
        submit_url=submit_url,
    )


def emailpass_hub_status(issuance_id: str):
    return issuance_status(SESSION_KEY, "emailpass", issuance_id)


def emailpass_hub_events(issuance_id: str):
    return issuance_events(SESSION_KEY, "emailpass", issuance_id)



def _delivery_serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt='emailpass-wallet-delivery-v1')


def emailpass_hub_send_offer():
    """Forward only this browser session's signed offer, never its verification code."""
    settings = current_app.extensions['issuer_settings']
    context = session.get('emailpass_delivery', {})
    try:
        signed = _delivery_serializer().loads(request.form.get('delivery_context', ''),
            max_age=settings.issuance_expires_in)
        if (not isinstance(signed, dict) or not context.get('nonce')
                or not hmac.compare_digest(signed.get('nonce', ''), context['nonce'])
                or signed.get('issuance_id') != session.get(SESSION_KEY)):
            raise BadSignature('Session mismatch')
        if context['expires_at'] <= time.time():
            raise SignatureExpired('Expired offer')
    except SignatureExpired:
        return jsonify(error='offer_expired', message='This offer has expired. Request a new one.'), 409
    except (BadSignature, TypeError, KeyError):
        return jsonify(error='invalid_session', message='Reload this offer page and try again.'), 403
    destination = request.form.get('wallet_address', '').strip()
    destination_hash = hashlib.sha256(destination.encode()).hexdigest()
    if context.get('sent_to'):
        if context['sent_to'] == destination_hash:
            return jsonify(status='offer_sent', message='Offer sent. Return to your wallet to review and accept it.')
        return jsonify(error='offer_already_sent', message='This offer has already been sent to a wallet.'), 409
    try:
        state = current_app.extensions['hub_client'].get_issuance(signed['issuance_id'])
        if state.get('status') in {'completed', 'failed', 'expired'}:
            return jsonify(error='offer_unavailable', message='This offer is no longer available.'), 409
        deliver_offer(destination, signed['offer'], settings)
    except WalletDeliveryError as error:
        return jsonify(error=error.code, message=str(error)), error.status
    except HubError:
        return jsonify(error='hub_unavailable', message='The offer could not be checked. Please try again.'), 502
    session['emailpass_delivery'] = {**context, 'sent_to': destination_hash}
    return jsonify(status='offer_sent', message='Offer sent. Return to your wallet to review and accept it.')
