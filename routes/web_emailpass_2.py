from flask import jsonify, request, render_template, session, redirect, flash
import json
from components import message
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import secrets
import base64
import subprocess

CODE_DELAY = timedelta(seconds= 180)

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"


def init_app(app,red, mode) :
    app.add_url_rule('/emailproof',  view_func=emailpass, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/emailpass',  view_func=emailpass, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/emailpass/authentication',  view_func=emailpass_authentication, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/emailpass/webhook',  view_func=emailpass_webhook, methods = ['POST'], defaults={'red' : red})
    app.add_url_rule('/emailpass/callback',  view_func=emailpass_callback, methods = ['GET', 'POST'])

    global link, client_secret
    if mode.myenv == 'aws':
        link = 'https://talao.co/sandbox/op/issuer/iagetctadx'
        client_secret = "1c6f9c32-1941-11ed-915c-0a1628958560"
    else :
        link = "http://192.168.0.65:3000/sandbox/op/issuer/fjogazfjkf"
        client_secret = "07134a8a-4bbd-11ed-8eba-757890ee2f5d"
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
        logging.info("email = %s ", session['email'])
        logging.info('email = %s', session['email'])
        session['code'] = "0"
        while len(session['code']) != 5 :
            session['code'] = str(secrets.randbelow(99999))
        session['code_delay'] = (datetime.now() + CODE_DELAY).timestamp()
        try : 
            subject = _('Altme pending email verification  ')
            message.messageHTML(subject, session['email'], 'code_auth_' + session['language'], {'code' : session['code']}, mode)
            logging.info('secret code sent = %s', session['code'])
            flash(_("Secret code sent to your email."), 'success')
            session['try_number'] = 1
        except :
            flash(_("Email failed."), 'danger')
            return render_template('emailpass/emailpass.html')
        return redirect ('emailpass/authentication')


def emailpass_authentication(red) :
    if not session.get('email') :
        return redirect ('/emailpass')
    # check secret code response
    if request.method == 'GET' :
        return render_template('emailpass/emailpass_authentication.html')
    if request.method == 'POST' :
        code = request.form['code']
        session['try_number'] +=1
        logging.info('code received = %s', code)
        if code == session['code'] and datetime.now().timestamp() < session['code_delay'] :
            # success exit, lets display a a QR code or an universal link in same session
            id = str(uuid.uuid1())
            red.set(id, session['email'])
            return redirect(link + '?id=' + id)
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

 

def emailpass_webhook(red):
    if request.headers.get("key") != client_secret :
        return jsonify("Forbidden"), 403
    data = request.get_json()
    logging.info("data = %s", data)
    
    if data['event'] == 'ISSUANCE' :
        email = red.get(data["id"]).decode()
        meta_data = json.dumps({"did" : data['vp']['holder'],
                         "email" : email})
        metadata = build_metadata(bytearray(meta_data, 'utf-8'))
        credential =  {
                "type" : "EmailPass",
                "email" : email,
                "passbaseMetadata" : metadata,
                "issuedBy" : {
                    "name" : "Altme",
                    } 
            }
        return jsonify(credential)
    
    if data['event'] == 'SIGNED_CREDENTIAL' :
        logging.info("credential issued = %s", data['vc'])
        return jsonify('ok')
 
def emailpass_callback() :
    message = _('Great ! you have now a proof of your email.')
    session.clear()
    return render_template('emailpass/emailpass_end.html', message=message)

