"""
https://issuer.talao.co/new/emailpass


choose your wallet
"""

from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from pathlib import Path
from functools import lru_cache
from components import message
from datetime import timedelta, datetime
import logging
from flask_babel import _
from random import randint
import requests
import uuid

logging.basicConfig(level=logging.INFO)

OFFER_DELAY = timedelta(seconds=10 * 60)
CODE_DELAY = timedelta(seconds=180)
QRCODE_DELAY = 60

OIDC4VC_URL = 'https://talao.co/sandbox/oidc4vc/issuer/api'
EMAILPASS_VC_PATH = 'verifiable_credentials/EmailPass.jsonld'
KEYS = json.load(open("keys.json", 'r'))

ISSUER_ID_JWT_VC_JSON_11 = 'zxhaokccsi'
client_secret_jwt_vc_json_11 = KEYS['client_secret_jwt_vc_json_11']

ISSUER_ID_LDP_VC = 'zijyqrygan'
client_secret_ldp_vc = KEYS['client_secret_ldp_vc']

ISSUER_ID_JWT_VC_JSON_13 = 'mslmgnysdh'
client_secret_jwt_vc_json_13 = KEYS['client_secret_jwt_vc_json']

ISSUER_LDP_VC_13 = 'lpiqylqrrs'
client_secret_ldp_vc_13 = KEYS['client_secret_ldp_vc_13']

ISSUER_ID_VC_SD_JWT = 'acnliwayop'
client_secret_vc_sd_jwt = KEYS['client_secret_vc_sd_jwt']

ISSUER_ID_VC_SD_JWT_15 = 'sdesntwqil'
client_secret_vc_sd_jwt_15 = KEYS['client_secret_vc_sd_jwt']

ISSUER_ID_VC_SD_JWT_18 = 'qpthwnsyyg'
client_secret_vc_sd_jwt_18 = KEYS['client_secret_vc_sd_jwt']

FORMAT_SUPPORTED = ["ldp_vc", "vc_sd_jwt", "jwt_vc_json", "jwt_vc_json-ld", "dc_sd_jwt"]
OIDC4VCI_DRAFT_SUPPORTED = ["10", "11", "13", "14", "15", "18"]


def init_app(app, red, mode):
    app.add_url_rule('/new/emailpass', view_func=new_emailpass, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/new/emailpass/oidc4vc', view_func=new_emailpass_oidc4vc, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/new/wallet-uri', view_func=new_wallet_uri, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/new/emailpass/oidc4vc/webhook', view_func=new_emailpass_oidc4vc_webhook, methods=['POST'],  defaults={'red': red})
    app.add_url_rule('/new/emailpass/authentication', view_func=new_emailpass_authentication, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/new/emailpass/stream',  view_func=new_emailpass_stream, methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/new/emailpass/follow_up/<session_id>',  view_func=new_emailpass_follow_up, methods=['GET', 'POST'], defaults={'red': red})


    app.add_url_rule('/wallet.json', view_func=wallet_json, methods=['GET'])
    return

def wallet_json():
    return jsonify(load_wallets())

@lru_cache(maxsize=1)
def load_wallets():
    with open("wallet.json", 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError('wallet.json must contain a list')
    return data


def find_wallet_by_name(wallet_name):
    wanted = str(wallet_name or '').strip().lower()
    for wallet in load_wallets():
        if str(wallet.get('name', '')).strip().lower() == wanted:
            return wallet
    return None


def normalize_format(wallet_format):
    raw = str(wallet_format or '').strip().lower()

    aliases = {
        'jwt_vc': 'jwt_vc_json',
        'jwt_vc_json': 'jwt_vc_json',
        'vc_sd_jwt': 'vc_sd_jwt',
        'vc+sd_jwt': 'vc_sd_jwt',
        'dc_sd_jwt': 'dc_sd_jwt',
        'dc+sd_jwt': 'dc_sd_jwt',
        'ldp_vc': 'ldp_vc',
        'jwt_vc_json-ld': 'jwt_vc_json-ld',
        'vcsd-jwt': 'vc_sd_jwt',
    }
    return aliases.get(raw, raw)


def get_wallet_request_payload():
    if request.method == 'POST':
        return request.get_json(silent=True) or {}
    return request.args.to_dict(flat=True)


def build_credential(email, credential_format):
    if credential_format in ['vc_sd_jwt', 'dc_sd_jwt']:
        return {
            "vct": "https://vc-registry.com/vct/registry/publish/2a6101b7c2207c7b6904a9215b25f4a556fe1b2c1c62debec96d5599d86a06a2",
            "vct#integrity": "sha256-7kCPECCGvCJoEt3XqTsIuVbaysGvb0O84Jtvsn6i/0A=",
            "email": email,
            "email_address": email,
            "email_verified": email,
            "disclosure": ["email", "email_address", "email_verified"]
        }

    credential = json.load(open(EMAILPASS_VC_PATH, 'r', encoding='utf-8'))
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['expirationDate'] = (datetime.utcnow() + timedelta(days=365)).replace(microsecond=0).isoformat() + 'Z'
    credential['credentialSubject']['email'] = email
    return credential


def get_issuer_configuration(credential_format, draft):
    if credential_format == 'ldp_vc':
        if draft in ["10", "11"]:
            return ISSUER_ID_LDP_VC, client_secret_ldp_vc
        elif draft == "13":
            return ISSUER_LDP_VC_13, client_secret_ldp_vc_13
        else:
            return None, None

    if credential_format == 'jwt_vc_json':
        if draft in  ["10", "11"]:
            return ISSUER_ID_JWT_VC_JSON_11, client_secret_jwt_vc_json_11
        elif draft == "13":
            return ISSUER_ID_JWT_VC_JSON_13, client_secret_jwt_vc_json_13
        else:
            return None, None
    
    if credential_format in ['vc_sd_jwt', 'dc_sd_jwt']:
        if draft == "13":
            return ISSUER_ID_VC_SD_JWT, client_secret_vc_sd_jwt
        elif draft == "15":
            return ISSUER_ID_VC_SD_JWT_15, client_secret_vc_sd_jwt_15
        elif draft == "18":
            return ISSUER_ID_VC_SD_JWT_18, client_secret_vc_sd_jwt_18
        else:
            return None, None
    
    return None, None


def new_emailpass(mode):
    if request.method == 'GET':
        session_id = str(uuid.uuid4())
        session["session_id"] = session_id
        return render_template('emailpass/new_emailpass.html', session_id=session_id)

    if request.method == 'POST':
        session['email'] = request.form['email'].lower()
        logging.info('email = %s', session['email'])
        session['code'] = str(randint(10000, 99999))
        session['code_delay'] = (datetime.now() + CODE_DELAY).timestamp()
        subject = _('Pending email verification ')       
        try:
            message.messageHTML(subject, session['email'], 'code_auth_en', {'code': session['code']}, mode)
            logging.info('secret code sent = %s', session['code'])
            flash(_('Secret code sent to your email.'), 'success')
            session['try_number'] = 1
        except Exception:
            logging.exception('Email failed')
            flash(_('Email failed.'), 'danger')
            return render_template('emailpass/new_emailpass.html')
        return redirect(mode.server + 'new/emailpass/authentication')
    return jsonify(), 404


def new_emailpass_authentication(mode):
    if not session.get('email'):
        return redirect(mode.server + 'new/emailpass')

    if request.method == 'GET':
        return render_template('emailpass/new_emailpass_authentication.html')

    if request.method == 'POST':
        code = request.form['code']

        session['try_number'] += 1
        logging.info('code received = %s', code)

        # success exit
        if code == session['code'] and datetime.now().timestamp() < session['code_delay']:
            return redirect(mode.server + 'new/emailpass/oidc4vc?session_id=' + session["session_id"])

        if session['code_delay'] < datetime.now().timestamp():
            flash(_('Code expired.'), 'warning')
            return render_template('emailpass/new_emailpass.html')

        if session['try_number'] > 3:
            flash(_('Too many trials (3 max).'), 'warning')
            return render_template('emailpass/new_emailpass.html')

        if session['try_number'] == 2:
            flash(_('This code is incorrect, 2 trials left.'), 'warning')
        if session['try_number'] == 3:
            flash(_('This code is incorrect, 1 trial left.'), 'warning')

        return render_template('emailpass/new_emailpass_authentication.html')


def new_emailpass_oidc4vc(mode):
    session_id = request.args.get("session_id")
    if not session.get('email'):
        return redirect(mode.server + 'new/emailpass')
    return render_template("emailpass/select_wallet.html", session_id=session_id)


def new_wallet_uri(mode):
    """
    Returns JSON to the frontend:
    {
        "wallet": "...",
        "draft": "...",
        "format": "...",
        "uri": "..."
    }
    """
    if not session.get('email'):
        return jsonify({"error": "email session missing"}), 401

    try:
        payload = get_wallet_request_payload()
        wallet_name = str(payload.get("wallet") or payload.get("name") or "").strip()

        if not wallet_name:
            return jsonify({"error": "wallet is required"}), 400

        wallet = find_wallet_by_name(wallet_name)
        if not wallet:
            return jsonify({"error": f"unknown wallet: {wallet_name}"}), 400

        draft = str(wallet.get("oidc4vci_draft", "")).strip()
        credential_format = normalize_format(wallet.get("format"))

        if draft not in OIDC4VCI_DRAFT_SUPPORTED:
            return jsonify({"error": f"unsupported draft: {draft}"}), 400

        if credential_format not in FORMAT_SUPPORTED:
            return jsonify({"error": f"unsupported format: {credential_format}"}), 400

        issuer_id, x_api_key = get_issuer_configuration(credential_format, draft)
        if not issuer_id or not x_api_key:
            return jsonify({"error": f"no issuer configuration for format={credential_format}, draft={draft}"}), 400

        credential = build_credential(session['email'], credential_format)

        headers = {
            'Content-Type': 'application/json',
            'X-API-KEY': x_api_key
        }

        data = {
            'vc': {'EmailPass': credential},
            'issuer_state': session.get("session_id"),
            'credential_type': ['EmailPass'],
            'pre-authorized_code': True,
            'user_pin_required': False,
            'webhook': mode.server + 'new/emailpass/oidc4vc/webhook',
            'callback': "Unused",
            'issuer_id': issuer_id
        }
        print("data = ", data)

        resp = requests.post(OIDC4VC_URL, headers=headers, json=data, timeout=10)
        resp.raise_for_status()

        body = resp.json()
        print("body = ", body)
        qrcode_uri = body.get('qrcode_value')

        if not qrcode_uri:
            logging.error('OIDC issuer response missing qrcode_value/redirect_uri: %s', body)
            return jsonify({"error": "issuer response missing qrcode uri"}), 502

        session['wallet'] = wallet_name
        session['draft'] = draft
        session['format'] = credential_format

        return jsonify({
            "wallet": wallet_name,
            "draft": draft,
            "format": credential_format,
            "uri": qrcode_uri
        }), 200

    except requests.RequestException:
        logging.exception('Error while calling OIDC issuer')
        return jsonify({"error": "issuer request failed"}), 502
    except Exception:
        logging.exception('Unexpected error in new_wallet_uri')
        return jsonify({"error": "internal server error"}), 500


def new_emailpass_oidc4vc_webhook(red):
    body = request.get_json(silent=True) or {}
    red.publish('new_emailpass', json.dumps(body))
    return jsonify("ok"), 200



def new_emailpass_follow_up(session_id, red):
    if request.args.get("message") == "ok":
        message_text = "Congratulations !"
    else:
        message_text = "Sorry, Error !"
    return render_template('emailpass/emailpass_end.html', message=message_text)


# server event
def new_emailpass_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('new_emailpass')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { 'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'}
    return Response(event_stream(red), headers=headers)