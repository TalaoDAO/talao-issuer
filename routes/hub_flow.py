"""Shared status and SSE handling for hub-backed proof flows."""

from __future__ import annotations

import json
import logging
import re
import time

from flask import Response, current_app, flash, jsonify, render_template, request, session

from components.openid4vc_hub import HubError
from routes.counter import record_completed_issuance

LOGGER = logging.getLogger(__name__)
TERMINAL_STATUSES = {"completed", "failed", "expired"}


def _safe_status(client, issuance_id: str) -> tuple[dict, int]:
    try:
        payload = client.get_issuance(issuance_id)
    except HubError as exc:
        temporary = exc.status_code >= 500
        return {
            "status": "pending" if temporary else "failed",
            "error": "hub_temporarily_unavailable" if temporary else "hub_error",
            "error_description": str(exc),
        }, exc.status_code

    status = payload.get("status", "pending")
    if not isinstance(status, str):
        status = "pending"
    result = {"status": status}
    for key in ("error", "error_description"):
        if isinstance(payload.get(key), str):
            result[key] = payload[key]
    return result, 200


def _record_if_completed(store, settings, counter_type, issuance_id, payload):
    if payload.get("status") != "completed":
        return
    try:
        record_completed_issuance(
            store,
            settings,
            counter_type,
            issuance_id,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        LOGGER.exception("Completed issuance could not be counted")


def issuance_status(session_key: str, counter_type: str, issuance_id: str):
    if issuance_id != session.get(session_key):
        return jsonify({"error": "forbidden"}), 403

    client = current_app.extensions["hub_client"]
    store = current_app.extensions["counter_store"]
    settings = current_app.extensions["issuer_settings"]
    payload, status_code = _safe_status(client, issuance_id)
    _record_if_completed(store, settings, counter_type, issuance_id, payload)
    return jsonify(payload), status_code


def issuance_events(session_key: str, counter_type: str, issuance_id: str):
    if issuance_id != session.get(session_key):
        return jsonify({"error": "forbidden"}), 403

    client = current_app.extensions["hub_client"]
    store = current_app.extensions["counter_store"]
    settings = current_app.extensions["issuer_settings"]

    def event_stream():
        last_serialized = None
        last_event_at = 0.0
        deadline = time.monotonic() + settings.issuance_expires_in + 30

        while True:
            payload, status_code = _safe_status(client, issuance_id)
            if (
                time.monotonic() >= deadline
                and payload["status"] not in TERMINAL_STATUSES
            ):
                payload = {
                    "status": "expired",
                    "error_description": "The credential offer has expired.",
                }
                status_code = 200

            _record_if_completed(store, settings, counter_type, issuance_id, payload)
            event_payload = {**payload, "http_status": status_code}
            serialized = json.dumps(event_payload, ensure_ascii=False)
            if serialized != last_serialized:
                yield f"data: {serialized}\n\n"
                last_serialized = serialized
                last_event_at = time.monotonic()
            elif time.monotonic() - last_event_at >= 15:
                yield ": keep-alive\n\n"
                last_event_at = time.monotonic()

            if payload["status"] in TERMINAL_STATUSES:
                break
            time.sleep(settings.event_poll_interval)

    return Response(
        event_stream(),
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def verify_contact_on_site(*, store_key, session_key, issuer, submit_url,
                           field_name, normalize, mask, send_code, start_form,
                           invalid_message, delivery_error, proof_name, contact_name, icon):
    """Return (verified subject, response); consume a challenge before creating an offer."""
    settings = current_app.extensions["issuer_settings"]
    store = current_app.extensions[store_key]
    token = session.get(session_key)
    action = request.form.get("action", "start")

    def form(pending, challenge):
        return render_template(
            "email_verify.html", masked_subject=mask(pending["subject"]),
            submit_url=pending["submit_url"], challenge_token=challenge,
            contact_name=contact_name, icon=icon,
        )

    def reject(message, status=400):
        flash(message, "danger")
        return None, (start_form(), status)

    if action in {"verify", "resend"} and (
        not token or request.form.get("challenge_token") != token
    ):
        return None, (start_form(), 403)
    pending = store.get(token)
    if action in {"verify", "resend"} and (not pending or pending["issuer"] != issuer):
        return reject("This verification has expired. Request a new code.")
    if action == "verify":
        digits = request.form.getlist("digit")
        code = "".join(digits)
        if len(digits) != 6 or any(not re.fullmatch(r"[0-9]", digit) for digit in digits):
            code = "invalid"
        result, verified = store.verify(token, code)
        if result == "verified":
            session.pop(session_key, None)
            return verified["subject"], None
        if result == "invalid":
            flash("Incorrect code. Please try again.", "danger")
            return None, (form(pending, token), 400)
        session.pop(session_key, None)
        return reject("The code has expired or too many attempts were made. Request a new code.")
    if action not in {"start", "resend"}:
        return None, (start_form(), 400)
    subject = pending["subject"] if action == "resend" else normalize(request.form.get(field_name, ""))
    if not subject:
        return reject(invalid_message)
    challenge = store.start(token, subject, issuer, submit_url)
    if challenge is None:
        flash("Please wait 60 seconds before requesting another code.", "danger")
        return None, (form(pending, token), 429)
    token, code = challenge
    session[session_key] = token
    try:
        if send_code(subject, code, settings) is False:
            raise RuntimeError("Code delivery failed")
    except Exception:
        store.discard(token)
        session.pop(session_key, None)
        current_app.logger.warning("%s code delivery failed", proof_name)
        return reject(delivery_error, 502)
    # Use a local record for rendering; a concurrent resend can invalidate the stored one.
    return None, form({"subject": subject, "submit_url": submit_url}, token)
