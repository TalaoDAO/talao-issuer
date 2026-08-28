"""Flask application factory for Proof of Email and Proof of Phone."""

from __future__ import annotations

import logging

from flask import Flask, jsonify, render_template

from components.openid4vc_hub import HubClient
from environment import Settings, load_settings
from routes import counter, emailpass_openid4vc_hub, phonepass_openid4vc_hub


def create_app(
    settings: Settings | None = None,
    *,
    hub_client=None,
    counter_store=None,
) -> Flask:
    settings = settings or load_settings()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings.secret_key,
        MAX_CONTENT_LENGTH=64 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.secure_cookies,
    )

    app.extensions["issuer_settings"] = settings
    app.extensions["hub_client"] = hub_client or HubClient(
        settings.hub_url,
        settings.hub_api_key,
        settings.hub_request_timeout,
    )
    app.extensions["counter_store"] = counter_store or counter.CounterStore(
        settings.counter_path
    )

    emailpass_openid4vc_hub.init_app(app)
    phonepass_openid4vc_hub.init_app(app)
    counter.init_app(app, settings)

    @app.get("/")
    def home():
        return render_template("home.html")

    @app.get("/healthz")
    def health():
        return jsonify({"status": "ok"})

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "request_too_large"}), 413

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error("Unhandled application error: %s", type(error).__name__)
        return jsonify({"error": "internal_server_error"}), 500

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    runtime_settings = load_settings()
    create_app(runtime_settings).run(
        host=runtime_settings.host,
        port=runtime_settings.port,
        debug=False,
    )
