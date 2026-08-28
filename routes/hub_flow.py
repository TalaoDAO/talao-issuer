"""Shared status and SSE handling for hub-backed proof flows."""

from __future__ import annotations

import json
import logging
import time

from flask import Response, current_app, jsonify, session

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
