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
    app.add_url_rule('/phonepass/redirect',  view_func=phonepass_redirect, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/phonepass/webhook',  view_func=phonepass_webhook, methods = ['POST'], defaults={'red' : red})
    app.add_url_rule('/phonepass/callback',  view_func=phonepass_callback, methods = ['GET', 'POST'])
    app.add_url_rule('/phonepass/authentication',  view_func=phonepass_authentication, methods = ['GET', 'POST'], defaults={'red' : red})
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


def phonepass_authentication(red) :
    if request.method == 'GET' :
        return render_template('phonepass/phonepass_authentication.html')
    if request.method == 'POST' :
        code = request.form['code']
        session['try_number'] +=1
        logging.info('code received = %s', code)
        if code == session['code'] and datetime.now().timestamp() < session['code_delay'] :
            id = str(uuid.uuid1())
            red.set(id, session['phone'])
    	    # success exit
            return redirect('/phonepass/redirect?id=' + id)
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


def phonepass_redirect(mode) :
    global client_secret
    if mode.myenv != 'aws':
        link = 'http://192.168.0.123:3000/sandbox/op/issuer/lrggujxcee?id=' + request.args.get('id')
        client_secret = "2678134c-1c97-11ed-9222-d9af830f0c58"
    else :
        link = 'https://talao.co/sandbox/op/issuer/iagetctadx?id=' + request.args.get('id')
        client_secret = "1c6f9c32-1941-11ed-915c-0a1628958560"
    return redirect (link)


def phonepass_webhook(red):
    key = request.headers.get("key")
    logging.info("key = %s", key)
    # TODO test against client_secret
    data = request.get_json()
    logging.info("data = %s", data)

    phone = red.get(data["id"]).decode()
    credential = {
        "credentialSubject" : {
            "type" : "PhonePass",
            "phone" : phone,
            "issuedBy" : {
                "name" : "Talao",
                "logo" : "https://talao.mypinata.cloud/ipfs/QmNwbEEupT7jR2zmrA87FsN4hUS8eXnCxM8DsL9RXc25cu"
            } 
        }
    }
    return jsonify(credential)
 

def phonepass_callback() :
    message = _('Great ! you have now a proof of phone number.')
    session.clear()
    return render_template('phonepass/phonepass_end.html', message=message)

