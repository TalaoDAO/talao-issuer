from flask import jsonify, request, render_template, session, redirect, flash, Response
from components import sms, message
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
from random import randint
import json
from urllib.parse import urlencode
import didkit
import requests

OFFER_DELAY = timedelta(seconds= 10*60)
CODE_DELAY = timedelta(seconds=180)
QRCODE_DELAY = 60

OIDC4VC_URL = 'https://talao.co/sandbox/oidc4vc/issuer/api'

ISSUER_ID_JWT_VC_JSON = 'tjxhjeilzg' # draft 11
client_secret_jwt_vc_json = json.load(open('keys.json', 'r'))['client_secret_jwt_vc_json']

ISSUER_ID_LDP_VC = 'iqztwpioef'
client_secret_ldp_vc = json.load(open('keys.json', 'r'))['client_secret_ldp_vc']

ISSUER_ID_JWT_VC_JSON_13 = 'mslmgnysdh'
client_secret_jwt_vc_json_13 = json.load(open('keys.json', 'r'))['client_secret_jwt_vc_json']
issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"


def init_app(app, red, mode):
    app.add_url_rule('/phonepass',  view_func=phonepass, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/phoneproof',  view_func=phonepass, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/phonepass/authentication',  view_func=phonepass_authentication, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/phonepass/qrcode',  view_func=phonepass_qrcode, methods=['GET', 'POST'], defaults={'mode': mode, 'red': red})
    app.add_url_rule('/phonepass/offer/<id>',  view_func=phonepass_enpoint, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/phonepass/stream',  view_func=phonepass_stream, methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/phonepass/end',  view_func=phonepass_end, methods=['GET', 'POST'])
    app.add_url_rule('/phonepass/oidc4vc',  view_func=phonepass_oidc4vc, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/phonepass/oidc4vc/callback',  view_func=phonepass_oidc4vc_callback, methods=['GET', 'POST'])
    return


def phonepass(mode):
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
        return render_template('phonepass/phonepass.html')
    elif request.method == 'POST':
        # traiter phone
        session['phone'] = request.form['phone']
        session['code'] = str(randint(10000, 99999))
        session['code_delay'] = (datetime.now() + CODE_DELAY).timestamp()
        try: 
            sms.send_code(session['phone'], session['code'], mode)
            logging.info('secret code sent = %s', session['code'])
            flash(_("Secret code sent to your phone."), 'success')
            session['try_number'] = 1
        except Exception:
            flash(_("phone failed."), 'danger')
            return render_template('phonepass/phonepass.html')
        return redirect('phonepass/authentication')
    else:
        return jsonify("Unauthorized"), 404


def phonepass_authentication(mode):
    if not session.get('phone'):
        return redirect('/phonepass')
    # check secret code response
    if request.method == 'GET':
        return render_template('phonepass/phonepass_authentication.html')
    if request.method == 'POST':
        code = request.form['code']
        session['try_number'] += 1
        logging.info('code received = %s', code)
        if code == session['code'] and datetime.now().timestamp() < session['code_delay']:
            # success exit, lets display a a QR code or an universal link in same session
            if session['format'] == 'ldp_vc' and session['draft'] == "11":
                return redirect(mode.server + 'phonepass/oidc4vc?draft=11&format=ldp_vc')
            elif session['format'] == 'ldp_vc' and session['draft'] == "0":
                return redirect(mode.server + 'phonepass/qrcode')
            else:
                return redirect(mode.server + 'phonepass/oidc4vc?draft=11&format=jwt_vc_json')
        elif session['code_delay'] < datetime.now().timestamp():
            flash(_("Code expired."), "warning")
            return render_template('phonepass/phonepass.html')
        elif session['try_number'] > 3:
            flash(_("Too many trials (3 max)."), "warning")
            return render_template('phonepass/phonepass.html')
        else:
            if session['try_number'] == 2:
                flash(_('This code is incorrect, 2 trials left.'), 'warning')
            if session['try_number'] == 3:
                flash(_('This code is incorrect, 1 trial left.'), 'warning')
            return render_template("phonepass/phonepass_authentication.html")


def phonepass_qrcode(red, mode):
    if not session.get('phone'):
        return redirect('/phonepass')
    id = str(uuid.uuid1())
    qr_code = mode.server + "phonepass/offer/" + id 
    logging.info('qr code = %s', qr_code)
    deeplink_talao = mode.deeplink_talao + 'app/download?' + urlencode({'uri': qr_code})
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri': qr_code})
    if not session.get('phone'):
        flash(_("Code expired."), "warning")
        return render_template('phonepass/phonepass.html')
    red.setex(id, QRCODE_DELAY, session['phone'])  # phone is stored in redis with id as index
    return render_template(
        'phonepass/phonepass_qrcode.html',
        url=qr_code,
        id=id,
        deeplink_talao=deeplink_talao,
        deeplink_altme=deeplink_altme
    )


async def phonepass_enpoint(id, red, mode):
    credential = json.load(open('./verifiable_credentials/PhoneProof.jsonld', 'r'))
    credential["issuer"] = issuer_did 
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (datetime.now() + timedelta(days=365)).isoformat() + "Z"
    credential['id'] = "urn:uuid:" + str(uuid.uuid1())
    if request.method == 'GET': 
        # make an offer  
        credential_manifest = json.load(open('./credential_manifest/phone_credential_manifest.json', 'r'))
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['credentialSubject']['id'] = "did:wallet"
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires": (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat(),
            "credential_manifest": credential_manifest
        }
        return jsonify(credential_offer)
    else:  # POST
        try:
            credential['credentialSubject']['phone'] = red.get(id).decode()
            red.delete(id)
        except Exception:
            logging.error('redis data expired')
            data = json.dumps({"id": id, "check": "expired"})
            red.publish('phonepass', data)
            return jsonify('session expired'), 408
        # init credential
        credential['credentialSubject']['id'] = request.form.get('subject_id', 'unknown DID')
        # signature 
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
            }
        signed_credential = await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        
        # update counter
        data = {"vc": "phonepass", "count": "1"}
        requests.post(mode.server + 'counter/update', data=data)

        # Success: send event to client agent to go forward
        data = json.dumps({"id": id, "check": "success"})
        red.publish('phonepass', data)
        
        # send message
        message.message("PhonePass sent", "thierry@altme.io", credential['credentialSubject']['phone'], mode)
        return jsonify(signed_credential)


def phonepass_oidc4vc(mode):
    if not session.get('phone'):
        return redirect('/phonepass')
    draft = session['draft']
    format = session['format']
    credential = json.load(open('./verifiable_credentials/PhoneProof.jsonld', 'r'))
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
    credential['expirationDate'] = (datetime.now() + timedelta(days=365)).isoformat() + 'Z'
    credential['credentialSubject']['phone'] = session['phone']
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
        return redirect('/phonepass')
    logging.info('issuer id = %s', issuer_id)
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': x_api_key
    }
    data = {
        'vc': {'PhoneProof': credential},
        'issuer_state': 'code',
        'credential_type': ['PhoneProof'],
        'pre-authorized_code': True,
        'user_pin_required': False,
        'callback': mode.server + 'phonepass/oidc4vc/callback',
        'issuer_id': issuer_id
    }
    try:
        resp = requests.post(OIDC4VC_URL, headers=headers, data=json.dumps(data))
        redirect_uri = resp.json()['redirect_uri']
    except Exception:
        logging.error('error oidc, redirect uri not available')
        return redirect('/phonepass')
    return redirect(redirect_uri)


def phonepass_oidc4vc_callback():
    if request.args.get('error'):
        message = 'Sorry ! there is a server problem, try again later.'
    else:
        message = 'Great ! you have now a proof of phone number.'
    return render_template('phonepass/phonepass_end.html', message=message)


def phonepass_end():
    if not session.get('phone'):
        return redirect('/phonepass')
    if request.args['followup'] == "success":
        message = _('Great ! you have now a proof of phone.')
    elif request.args['followup'] == 'expired':
        message = _('Sorry ! session expired.')
    else:
        message = _('Sorry ! there is a server problem, try again later.')
    session.clear()
    return render_template('phonepass/phonepass_end.html', message=message)


# server event
def phonepass_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('phonepass')
        for event_message in pubsub.listen():
            if event_message['type'] == 'message':
                yield 'data: %s\n\n' % event_message['data'].decode()
    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no"
    }
    return Response(event_stream(red), headers=headers)
