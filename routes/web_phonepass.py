from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from components import sms
import uuid
import secrets
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
from urllib.parse import urlencode
import didkit

OFFER_DELAY = timedelta(seconds= 30)
CODE_DELAY = timedelta(seconds= 180)
QRCODE_DELAY = 30


key_tz1 = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
vm_tz1 = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
issuer_did =  "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"


def init_app(app,red, mode) :
    app.add_url_rule('/phonepass',  view_func=phonepass, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/phonepass/qrcode',  view_func=phonepass_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode, 'red' : red})
    app.add_url_rule('/phonepass/offer/<id>',  view_func=phonepass_offer_endpoint, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/phonepass/authentication',  view_func=phonepass_authentication, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/phonepass/stream',  view_func=phonepass_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/phonepass/end',  view_func=phonepass_end, methods = ['GET', 'POST'])
    return


def phonepass(mode) :
    if request.method == 'GET' :
        return render_template('phonepass/phonepass.html')
    if request.method == 'POST' :
        # traiter phone
        session['phone'] = request.form['phone']
        session['code'] = str(secrets.randbelow(99999))
        session['code_delay'] = (datetime.now() + CODE_DELAY).timestamp()
        try : 
            sms.send_code(session['phone'], session['code'], mode)
            logging.info('secret code sent = %s', session['code'])
            flash(_("Secret code sent to your phone."), 'success')
            session['try_number'] = 1
        except :
            flash(_("phone failed."), 'danger')
            return render_template('phonepass/phonepass.html')
        return redirect ('phonepass/authentication')


def phonepass_authentication(mode) :
    if request.method == 'GET' :
        return render_template('phonepass/phonepass_authentication.html')
    if request.method == 'POST' :
        code = request.form['code']
        session['try_number'] +=1
        logging.info('code received = %s', code)
        if code == session['code'] and datetime.now().timestamp() < session['code_delay'] :
    	    # success exit
            return redirect(mode.server + 'phonepass/qrcode')
        elif session['code_delay'] < datetime.now().timestamp() :
            flash(_("Code expired."), "warning")
            return render_template('phonepass/phonepass.html')
        elif session['try_number'] > 3 :
            flash(_("Too many trials (3 max)."), "warning")
            return render_template('phonepass/phonepass.html')
        else :
            if session['try_number'] == 2 :
                flash(_('This code is incorrect, 2 trials left.'), 'warning')
            if session['try_number'] == 3 :
                flash(_('This code is incorrect, 1 trial left.'), 'warning')
            return render_template("phonepass/phonepass_authentication.html")


def phonepass_qrcode(red, mode) :
    id = str(uuid.uuid1())
    qr_code = mode.server + "phonepass/offer/" + id +'?' + urlencode({'issuer' : issuer_did})
    deeplink_talao = mode.deeplink_talao + 'app/download?' + urlencode({'uri' : qr_code })
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri' : qr_code })
    if not session.get('phone') :
        flash(_("Code expired."), "warning")
        return render_template('phonepass/phonepass.html')
    red.setex(id, QRCODE_DELAY, session['phone'])
    return render_template('phonepass/phonepass_qrcode.html',
                                url=qr_code,
                                id=id,
                                deeplink_talao=deeplink_talao,
                                deeplink_altme=deeplink_altme)
   

async def phonepass_offer_endpoint(id, red):
    credential = json.loads(open('./verifiable_credentials/PhonePass.jsonld', 'r').read())
    credential["issuer"] = issuer_did
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['credentialSubject']['phone'] = red.get(id).decode()
    credential['expirationDate'] =  (datetime.utcnow().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"

    if request.method == 'GET': 
        credential['id'] = "urn:uuid:random"
        credential['credentialSubject']['id'] = "did:wallet"
        credential_manifest = json.load(open('./credential_manifest/phone_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
    
        # make an offer  
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)
    if request.method == 'POST': 
        red.delete(id)   
        # sign credential
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form['subject_id']
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": vm_tz1
            }
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key_tz1)
        if not signed_credential :
            logging.error('credential signature failed')
            data = json.dumps({"url_id" : id, "check" : "failed"})
            red.publish('phonepass', data)
            return jsonify('server error'), 500
        # send event to client agent to go forward
        data = json.dumps({"url_id" : id, "check" : "success"})
        red.publish('phonepass', data)
        return jsonify(signed_credential)
 

def phonepass_end() :
    if request.args['followup'] == "success" :
        message = _('Great ! you have now a proof of phone number.')
    elif request.args['followup'] == 'expired' :
        message = _('Sorry, session expired.')
    else :
        message = _('Sorry, server problem, try again later.')
    return render_template('phonepass/phonepass_end.html', message=message)


# server event push 
def phonepass_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('phonepass')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
