from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from components import message
import uuid
from datetime import timedelta, datetime
import logging
from flask_babel import _
from urllib.parse import urlencode
import didkit
from random import randint
import requests

logging.basicConfig(level=logging.INFO)
OFFER_DELAY = timedelta(seconds=10*60)
CODE_DELAY = timedelta(seconds=180)
QRCODE_DELAY = 60

OIDC4VC_URL = 'https://talao.co/sandbox/oidc4vc/issuer/api'

ISSUER_ID_JWT_VC_JSON = 'tjxhjeilzg'
client_secret_jwt_vc_json = json.load(open('keys.json', 'r'))['client_secret_jwt_vc_json']

ISSUER_ID_LDP_VC = 'iqztwpioef'
client_secret_ldp_vc = json.load(open('keys.json', 'r'))['client_secret_ldp_vc']

ISSUER_ID_JWT_VC_JSON_13 = 'mslmgnysdh'
client_secret_jwt_vc_json_13 = json.load(open('keys.json', 'r'))['client_secret_jwt_vc_json']

issuer_key = json.dumps(json.load(open('keys.json', 'r'))['talao_Ed25519_private_key'])
issuer_vm = 'did:web:app.altme.io:issuer#key-1'
issuer_did = 'did:web:app.altme.io:issuer'


def init_app(app, red, mode):
    app.add_url_rule('/emailproof',  view_func=emailpass, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/emailpass',  view_func=emailpass, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/emailpass/qrcode',  view_func=emailpass_qrcode, methods=['GET', 'POST'], defaults={'mode': mode, 'red': red})
    app.add_url_rule('/emailpass/oidc4vc',  view_func=emailpass_oidc4vc, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/emailpass/oidc4vc/callback',  view_func=emailpass_oidc4vc_callback, methods=['GET', 'POST'])

    app.add_url_rule('/emailpass/offer/<id>',  view_func=emailpass_enpoint, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/emailpass/authentication',  view_func=emailpass_authentication, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/emailpass/stream',  view_func=emailpass_stream, methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/emailpass/end',  view_func=emailpass_end, methods=['GET', 'POST'])
    return


def emailpass(mode):
    # request email to user and send a secret code
    if request.method == 'GET':
        if request.args.get('format') == 'jwt_vc_json':
            format = 'jwt_vc_json'
        else:
            format = 'ldp_vc'
        if not request.args.get('draft') and format == 'ldp_vc':
            draft = "0"
        elif not request.args.get('draft'):
            draft = "11"
        else:
            draft = request.args.get('draft')
        logging.info('VC format is %s', format)
        logging.info('VC draft is %s', draft)
        session['draft'] = draft
        session['format'] = format
        return render_template('emailpass/emailpass.html')
    elif request.method == 'POST':
        session['email'] = request.form['email'].lower()
        logging.info('email = %s', session['email'])
        session['code'] = str(randint(10000, 99999))
        session['code_delay'] = (datetime.now() + CODE_DELAY).timestamp()
        subject = _('Altme pending email verification ')
        if session['email'].split('@')[1] == 'wallet-provider.io':
            session['try_number'] = 1
            logging.info('wallet provider email request')
        elif message.messageHTML(subject, session['email'], 'code_auth_en', {'code': session['code']}, mode):
            logging.info('secret code sent = %s', session['code'])
            flash(_('Secret code sent to your email.'), 'success')
            session['try_number'] = 1
        else:
            flash(_('Email failed.'), 'danger')
            return render_template('emailpass/emailpass.html')
        return redirect('emailpass/authentication')
    else:
        return jsonify(), 404


def emailpass_authentication(mode):
    if not session.get('email'):
        return redirect('/emailpass')
    # check secret code response
    if request.method == 'GET':
        return render_template('emailpass/emailpass_authentication.html')
    if request.method == 'POST':
        code = request.form['code']
        if code == mode.wallet_provider and session['email'].split('@')[1] == 'wallet-provider.io':
            return redirect(mode.server + 'emailpass/qrcode')
        session['try_number'] += 1
        logging.info('code received = %s', code)
        if code == session['code'] and datetime.now().timestamp() < session['code_delay']:
        # success exit, lets display a a QR code or an universal link in same session
            if session['format'] == 'ldp_vc' and session['draft'] == "11":
                return redirect(mode.server + 'emailpass/oidc4vc?draft=11&format=ldp_vc')
            elif session['format'] == 'ldp_vc' and session['draft'] == "0":
                return redirect(mode.server + 'emailpass/qrcode')
            else:
                return redirect(mode.server + 'emailpass/oidc4vc?draft=11&format=jwt_vc_json')
        elif session['code_delay'] < datetime.now().timestamp():
            flash(_('Code expired.'), 'warning')
            return render_template('emailpass/emailpass.html')
        elif session['try_number'] > 3:
            flash(_('Too many trials (3 max).'), 'warning')
            return render_template('emailpass/emailpass.html')
        else:
            if session['try_number'] == 2:
                flash(_('This code is incorrect, 2 trials left.'), 'warning')
            if session['try_number'] == 3:
                flash(_('This code is incorrect, 1 trial left.'), 'warning')
            return render_template('emailpass/emailpass_authentication.html')


def emailpass_qrcode(red, mode):
    if not session.get('email'):
        return redirect('/emailpass')
    id = str(uuid.uuid1())
    qr_code = mode.server + 'emailpass/offer/' + id + '?issuer=' + issuer_did
    logging.info('qr code = %s', qr_code)
    deeplink_talao = mode.deeplink_talao + 'app/download?' + urlencode({'uri': qr_code})
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri': qr_code})
    if not session.get('email'):
        flash(_('Code expired.'), 'warning')
        return render_template('emailpass/emailpass.html')
    red.setex(id, QRCODE_DELAY, session['email'])  # email is stored in redis with id as index
    return render_template(
        'emailpass/emailpass_qrcode.html',
        url=qr_code,
        id=id,
        deeplink_talao=deeplink_talao,
        deeplink_altme=deeplink_altme
    )


async def emailpass_enpoint(id, red, mode):
    credential = json.load(open('./verifiable_credentials/EmailPass.jsonld', 'r'))
    credential['issuer'] = issuer_did 
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
    credential['expirationDate'] = (datetime.now() + timedelta(days=365)).isoformat() + 'Z'
    credential['id'] = 'urn:uuid:' + str(uuid.uuid1())
    if request.method == 'GET': 
        # make an offer  
        credential_manifest = json.load(open('./credential_manifest/email_credential_manifest.json', 'r'))
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['credentialSubject']['id'] = 'did:wallet'
        credential_offer = {
            'type': 'CredentialOffer',
            'credentialPreview': credential,
            'expires': (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat(),
            'credential_manifest': credential_manifest
        }
        return jsonify(credential_offer)
    else:  # POST
        try:
            credential['credentialSubject']['email'] = red.get(id).decode()
        except Exception:
            logging.error('redis data expired')
            data = json.dumps({'id': id, 'check': 'expired'})
            red.publish('emailpass', data)
            return jsonify('Session expired'), 412
        credential['credentialSubject']['id'] = request.form.get('subject_id', 'unknown DID')
        # signature 
        didkit_options = {
            'proofPurpose': 'assertionMethod',
            'verificationMethod': issuer_vm
        }
        signed_credential = await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        
        # update counter
        data = {
            'vc': 'emailpass',
            'count': '1'
        }
        requests.post(mode.server + 'counter/update', data=data)

        # Success: send event to client agent to go forward
        data = json.dumps({
            'id': id,
            'check': 'success'
        })
        red.publish('emailpass', data)
        message.message('EmailPass sent', 'thierry@altme.io', credential['credentialSubject']['email'], mode)
        return jsonify(signed_credential)


def emailpass_oidc4vc(mode):
    if not session.get('email'):
        return redirect('/emailpass')
    draft = session['draft']
    format = session['format']
    credential = json.load(open('./verifiable_credentials/EmailPass.jsonld' , 'r'))
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
    credential['expirationDate'] = (datetime.now() + timedelta(days= 365)).isoformat() + 'Z'
    credential['credentialSubject']['email'] = session['email']
    # call to sandbox issuer
    if format == 'ldp_vc' and draft == "11":
        x_api_key = client_secret_ldp_vc
        issuer_id = ISSUER_ID_LDP_VC
    elif format == 'jwt_vc_json' and draft == "11":
        x_api_key = client_secret_jwt_vc_json
        issuer_id = ISSUER_ID_JWT_VC_JSON
    elif format == 'jwt_vc_json' and draft == "13":
        x_api_key = client_secret_jwt_vc_json_13
        issuer_id = ISSUER_ID_JWT_VC_JSON_13
    else:
        logging.error('draft or format not supported')
        return redirect('/emailpass')
    logging.info('issuer id = %s', issuer_id)
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': x_api_key
    }
    data = {
        'vc': {'EmailPass': credential},
        'issuer_state': 'code',
        'credential_type': ['EmailPass'],
        'pre-authorized_code': True,
        'user_pin_required': False,
        'callback': mode.server + 'emailpass/oidc4vc/callback',
        'issuer_id': issuer_id
    }
    try:
        resp = requests.post(OIDC4VC_URL, headers=headers, data=json.dumps(data))
        redirect_uri = resp.json()['redirect_uri']
    except Exception:
        logging.error('error oidc, redirect uri not available')
        return redirect('/emailpass')
    return redirect(redirect_uri)


def emailpass_oidc4vc_callback():
    if request.args.get('error'):
        message = 'Sorry ! there is a server problem, try again later.'
    else:
        message = 'Great ! you have now a proof of email.'
    return render_template('emailpass/emailpass_end.html', message=message)


def emailpass_end():
    if not session.get('email'):
        return redirect('/emailpass')
    if request.args['followup'] == 'success':
        message = 'Great ! you have now a proof of email.'
    elif request.args['followup'] == 'expired':
        message = 'Sorry ! session expired.'
    else:
        message = 'Sorry ! there is a server problem, try again later.'
    session.clear()
    return render_template('emailpass/emailpass_end.html', message=message)


# server event
def emailpass_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('emailpass')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { 'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'}
    return Response(event_stream(red), headers=headers)