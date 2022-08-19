from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from components import message
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import secrets
from urllib.parse import urlencode
import didkit
import base64
import subprocess

OFFER_DELAY = timedelta(seconds= 10*60)
CODE_DELAY = timedelta(seconds= 180)
QRCODE_DELAY = 60

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"


def init_app(app,red, mode) :
    app.add_url_rule('/emailproof',  view_func=emailpass, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/emailpass',  view_func=emailpass, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/emailpass/qrcode',  view_func=emailpass_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode, 'red' : red})
    app.add_url_rule('/emailpass/offer/<id>',  view_func=emailpass_enpoint, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/emailpass/authentication',  view_func=emailpass_authentication, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/emailpass/stream',  view_func=emailpass_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/emailpass/end',  view_func=emailpass_end, methods = ['GET', 'POST'])
    return


def build_metadata(metadata) :
    # with passbase openssl signature scheme . cant find a python lib to do the same !!! 
    # cf Passbase documentation
    with open("passbase-private-key.pem", "rb") as f:
        p = subprocess.Popen(
            "/usr/bin/openssl rsautl -sign -inkey " + f.name,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, # signature
            stderr=subprocess.PIPE) # error
        signature, error = p.communicate(input=metadata)
        logging.error('erreur = %s', error)
        encrypted_metadata = base64.b64encode(signature)
    return encrypted_metadata.decode()


def emailpass(mode) :
    # request email to user and send a secret code
    if request.method == 'GET' :
        return render_template('emailpass/emailpass.html')
    if request.method == 'POST' :
        session['email'] = request.form['email'].lower()
        logging.info('email = %s', session['email'])
        session['code'] = str(secrets.randbelow(99999))
        session['code_delay'] = (datetime.now() + CODE_DELAY).timestamp()
        try : 
            subject = _('Email authentication  ')
            message.messageHTML(subject, session['email'], 'code_auth_' + session['language'], {'code' : session['code']}, mode)
            logging.info('secret code sent = %s', session['code'])
            flash(_("Secret code sent to your email."), 'success')
            session['try_number'] = 1
        except :
            flash(_("Email failed."), 'danger')
            return render_template('emailpass/emailpass.html')
        return redirect ('emailpass/authentication')


def emailpass_authentication(mode) :
    # check secret code response
    if request.method == 'GET' :
        return render_template('emailpass/emailpass_authentication.html')
    if request.method == 'POST' :
        code = request.form['code']
        session['try_number'] +=1
        logging.info('code received = %s', code)
        if code == session['code'] and datetime.now().timestamp() < session['code_delay'] :
    	    # success exit, lets display a a QR code or an universal link in same session
            return redirect(mode.server + 'emailpass/qrcode')
        elif session['code_delay'] < datetime.now().timestamp() :
            flash(_("Code expired."), "warning")
            return render_template('emailpass/emailpass.html')
        elif session['try_number'] > 3 :
            flash(_("Too many trials (3 max)."), "warning")
            return render_template('emailpass/emailpass.html')
        else :
            if session['try_number'] == 2 :
                flash(_('This code is incorrect, 2 trials left.'), 'warning')
            if session['try_number'] == 3 :
                flash(_('This code is incorrect, 1 trial left.'), 'warning')
            return render_template("emailpass/emailpass_authentication.html")


def emailpass_qrcode(red, mode) :
    id = str(uuid.uuid1())
    qr_code = mode.server + "emailpass/offer/" + id +'?' + urlencode({'issuer' : issuer_did})
    logging.info('qr code = %s', qr_code)
    deeplink_talao = mode.deeplink_talao + 'app/download?' + urlencode({'uri' : qr_code })
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri' : qr_code })

    if not session.get('email') :
        flash(_("Code expired."), "warning")
        return render_template('emailpass/emailpass.html')
    red.setex(id, QRCODE_DELAY, session['email']) # email is stored in redis with id as index
    return render_template('emailpass/emailpass_qrcode.html',
                                url=qr_code,
                                id=id,
                                deeplinktalao=deeplink_talao,
                                deeplink_altme=deeplink_altme)

   
async def emailpass_enpoint(id, red):
    credential = json.load(open('./verifiable_credentials/EmailPass.jsonld', 'r'))
    credential["issuer"] = issuer_did 
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
    try :
        credential['credentialSubject']['email'] = red.get(id).decode()
    except :
        logging.error('redis data expired')
        data = json.dumps({"id" : id, "check" : "expired"})
        red.publish('emailpass', data)
        return jsonify('session expired'), 408
    
    if request.method == 'GET': 
        # make an offer  
        credential_manifest = json.load(open('./credential_manifest/email_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        
        credential['id'] = "urn:uuid:random"
        credential['credentialSubject']['id'] = "did:wallet"
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat(),
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)

    else :  #POST
        #red.delete(id)   #TODO remove but remplace with set time = expiration delay
        # init credential
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form.get('subject_id', 'unknown DID')
        # build passbase metadata for KYC and Over18 credentials
        data = json.dumps({"did" : request.form.get('subject_id', 'unknown DID'),
                         "email" : credential['credentialSubject']['email']})
        credential['credentialSubject']['passbaseMetadata'] = build_metadata(bytearray(data, 'utf-8'))
        logging.info('metadata = %s', credential['credentialSubject']['passbaseMetadata'])
        # signature 
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
            }
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        if not signed_credential :         # send event to client agent to go forward
            logging.error('credential signature failed')
            data = json.dumps({"id" : id, "check" : "failed"})
            red.publish('emailpass', data)
            return jsonify('Server failed'), 500
        # Success : send event to client agent to go forward
        data = json.dumps({"id" : id, "check" : "success"})
        red.publish('emailpass', data)
        return jsonify(signed_credential)
 

def emailpass_end() :
    if request.args['followup'] == "success" :
        message = _('Great ! you have now a proof of email.')
    elif request.args['followup'] == 'expired' :
        message = _('Sorry ! session expired.')
    else :
        message = _('Sorry ! there is a server problem, try again later.')
    return render_template('emailpass/emailpass_end.html', message=message)


# server event
def emailpass_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('emailpass')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
