"""Persistent and idempotent counters for completed issuances."""

from __future__ import annotations

import fcntl
import hmac
import json
import logging
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import requests
from flask import current_app, jsonify, request

LOGGER = logging.getLogger(__name__)
COUNTER_TYPES = {"emailpass", "phonepass"}
PROCESSED_KEY = "_processed_issuances"
MAX_PROCESSED_ISSUANCES = 10_000


class CounterStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(f"{self.path.suffix}.lock")

    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _read(self) -> dict:
        try:
            with self.path.open(encoding="utf-8") as stream:
                data = json.load(stream)
        except FileNotFoundError:
            data = {}
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("Cannot read the counter store") from exc

        if not isinstance(data, dict):
            raise TypeError("The counter store must contain a JSON object")
        data.setdefault("total", 0)
        for counter_type in COUNTER_TYPES:
            data.setdefault(counter_type, 0)
        return data

    def _write(self, data: dict) -> None:
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as stream:
                temporary_path = Path(stream.name)
                json.dump(data, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.path)
        finally:
            if temporary_path and temporary_path.exists():
                temporary_path.unlink()

    @staticmethod
    def _public(data: dict) -> dict:
        return {
            "total": data["total"],
            "emailpass": data["emailpass"],
            "phonepass": data["phonepass"],
        }

    def snapshot(self) -> dict:
        with self._locked():
            return self._public(self._read())

    def increment(
        self,
        counter_type: str,
        *,
        count: int = 1,
        issuance_id: str | None = None,
    ) -> tuple[bool, dict]:
        if counter_type not in COUNTER_TYPES:
            raise ValueError("Unsupported counter type")
        if count <= 0:
            raise ValueError("Count must be positive")

        with self._locked():
            data = self._read()
            processed = data.setdefault(PROCESSED_KEY, {})
            if not isinstance(processed, dict):
                processed = {}
                data[PROCESSED_KEY] = processed

            if issuance_id and issuance_id in processed:
                return False, self._public(data)

            data[counter_type] = int(data[counter_type]) + count
            data["total"] = int(data["total"]) + count

            if issuance_id:
                processed[issuance_id] = int(time.time())
                while len(processed) > MAX_PROCESSED_ISSUANCES:
                    processed.pop(next(iter(processed)))

            self._write(data)
            return True, self._public(data)


def record_completed_issuance(store, settings, counter_type, issuance_id) -> bool:
    created, snapshot = store.increment(counter_type, issuance_id=issuance_id)
    if not created or not settings.slack_url:
        return created

    payload = {
        "channel": "#issuer_counter",
        "username": "issuer",
        "text": f"New {counter_type} issued {json.dumps(snapshot)}",
        "icon_emoji": ":ghost:",
    }
    try:
        requests.post(
            settings.slack_url,
            data={"payload": json.dumps(payload)},
            timeout=settings.hub_request_timeout,
        ).raise_for_status()
    except requests.RequestException:
        LOGGER.warning("Counter updated but Slack notification failed")
    return created


def init_app(app, settings):
    app.add_url_rule("/counter/get", view_func=counter_get, methods=["GET"])
    app.add_url_rule(
        "/counter/update",
        view_func=counter_update,
        methods=["POST"],
        defaults={"settings": settings},
    )


def counter_get():
    store = current_app.extensions["counter_store"]
    return jsonify(store.snapshot())


def counter_update(settings):
    """Compatibility endpoint; internal hub flows do not use this route."""

    supplied_key = request.headers.get("X-API-Key", "")
    if not settings.counter_api_key or not hmac.compare_digest(
        supplied_key,
        settings.counter_api_key,
    ):
        return jsonify({"error": "unauthorized"}), 401

    counter_type = request.form.get("vc", "").strip().lower()
    try:
        count = int(request.form.get("count", "1"))
        _, snapshot = current_app.extensions["counter_store"].increment(
            counter_type,
            count=count,
        )
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_request"}), 400
    return jsonify(snapshot)
