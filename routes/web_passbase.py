import sqlite3
from flask import jsonify, request, render_template, Response, render_template_string, session
import json
from datetime import timedelta, datetime
import didkit
import uuid
from urllib.parse import urlencode

import logging
from flask_babel import Babel, _
import sqlite3
import requests
from components import message

logging.basicConfig(level=logging.INFO)

OFFER_DELAY = timedelta(seconds= 10*60)
EXPIRATION_DELAY = timedelta(weeks=52)

key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"
vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"

 
def init_app(app,red, mode) :
    app.add_url_rule('/over18',  view_func=over18, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/kyc',  view_func=kyc, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/passbase/webhook',  view_func=passbase_webhook, methods = ['POST'], defaults={ 'mode' : mode})
    app.add_url_rule('/passbase/check/<did>',  view_func=passbase_check, methods = ['GET'])
    app.add_url_rule('/passbase/endpoint/over18/<id>',  view_func=passbase_endpoint_over18, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/idcard/<id>',  view_func=passbase_endpoint_idcard, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/stream',  view_func=passbase_stream, methods = ['GET', 'POST'], defaults={'red' :red})
    app.add_url_rule('/passbase/back',  view_func=passbase_back, methods = ['GET', 'POST'])
    return


def add_passbase_db(email, check, did, key, created) :
    conn = sqlite3.connect('passbase_check.db')
    c = conn.cursor()
    data = {'email' : email,                       
			 'status' : check,
             "did" : did,
             "key" : key,
             "created" : created}      
    c.execute("INSERT INTO webhook VALUES (:email, :status, :did, :key, :created)", data)
    conn.commit()
    conn.close()
    return


# curl http://:3000/passbase/check/OOO  -H "Accept: application/json"   -H "Authorization: Bearer mytoken"

def get_passbase_db(did) :
    """
    take the last one
    
    """
    conn = sqlite3.connect('passbase_check.db')
    c = conn.cursor()
    data = { "did" : did}
    c.execute("SELECT status, key, created FROM webhook WHERE did = :did", data)
    check = c.fetchall()
    logging.info("check = %s", check)
    conn.close()
    if len(check) == 1 :
        return check[0]
    try :
        return check[-1]
    except :
        return None


def passbase_check(did) :
    """
    return approved, declined, notdone
    last check
    
    """
    print("ok")
    check = get_passbase_db(did) 
    try :
        access_token = request.headers["Authorization"].split()[1]
        print("access token = ", access_token)
    except :
        pass
    if check :
        return jsonify(check[0])
    else :
        return jsonify("notdone")


def get_identity(passbase_key, mode) :
    url = "https://api.passbase.com/verification/v1/identities/" + passbase_key
    logging.info("API call url = %s", url)
    headers = {
        'accept' : 'application/json',
        'X-API-KEY' : mode.passbase
    }
    r = requests.get(url, headers=headers)
    logging.info("status code = %s", r.status_code)
    if not 199<r.status_code<300 :
        logging.error("API call rejected %s", r.status_code)
        return None
        
    # treatment of API data
    identity = r.json()
    return identity


def over18(mode) :
    id = str(uuid.uuid1())
    url_over18 = mode.server + "passbase/endpoint/over18/" + id +'?issuer=' + issuer_did
    deeplink_talao = mode.deeplink_talao + 'app/download?' + urlencode({'uri' : url_over18 })
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri' : url_over18 })
    return render_template('/passbase/over18.html',
                                url=url_over18,
                                deeplink_altme=deeplink_altme,
                                deeplink_talao=deeplink_talao,
                                id=id
                                )

def kyc(mode) :
    id = str(uuid.uuid1())
    url_idcard = mode.server + "passbase/endpoint/idcard/" + id +'?issuer=' + issuer_did
    deeplink_talao = mode.deeplink_talao + 'app/download?' + urlencode({'uri' : url_idcard })
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri' : url_idcard })
    return render_template('/passbase/kyc.html',
                                url=url_idcard,
                                deeplink_altme=deeplink_altme,
                                deeplink_talao=deeplink_talao,
                                id=id
                                )

"""
curl --location --request POST 'http://192.168.0.65:3000/passbase/webhook' \
--header 'Content-Type: application/json' \
--data-raw '{"event": "VERIFICATION_REVIEWED","key": "72be8407-a1df-47d7-af1b-e00f6ba4f96c", "status": "approved", "created" : 1582628712}'
"""
def passbase_webhook(mode) :
    # get email and id
    webhook = request.get_json()
    logging.info("webhook has received an event = %s", webhook)
    if webhook['event' ] in ["VERIFICATION_REVIEWED" , "VERIFICATION_COMPLETED"] :
        logging.info("identityKey = %s", webhook['key'])
        logging.info(webhook['event'])
    else :
        logging.warning("Verification not completed")
        return jsonify('Verification not completed')
    
    # get identity data from Passbase and set the issuer local database with minimum data
    identity = get_identity(webhook['key'], mode)
    if not identity :
        logging.error("probleme d acces API")
        return jsonify("probleme d acces API")

    email = identity['owner']['email']
    try :
        did = identity['metadata']['did']
    except :
        logging.error("Metadata are not available")
        link_text = "Sorry ! \nThe authentication failed.\nProbably your proof of email has been rejected.\nLet's try again with a new proof of email."
        message.message(_("Talao wallet identity credential"), email, link_text, mode)
        logging.warning("email sent to %s", email)
        return jsonify("No metadata")

    add_passbase_db(email,
                webhook['status'],
                did,
                webhook['key'],
                webhook['created'] )

    # send notification by email
    if webhook['status' ] == "approved" :
        link_text = "Great ! \n\nWe have now the proof your Identity.\nFollow the links in your wallet to get your credentials."
        message.message(_("Talao wallet identity credential"), email, link_text, mode)
        logging.info("email sent to %s", email)
        return jsonify('ok, notification sent')
    else :
        link_text = "Sorry ! \nThe authentication failed.\nProbably the identity documents are not acceptable.\nLet's try again with another type of document."
        message.message(_("Talao wallet identity credential"), email, link_text, mode)
        logging.info("email sent to %s", email)
        logging.warning('Identification not approved, no notification was sent')
        return jsonify("not approved")


async def passbase_endpoint_over18(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/Over18.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = "did:..."
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z"
        }
        red.set(id, json.dumps(credentialOffer))
        return jsonify(credentialOffer)

    try : 
        credentialOffer = json.loads(red.get(id).decode())
    except :
        logging.error("red get id error, or request time out ")
        return jsonify ('request time out'),408
    credential =  credentialOffer['credentialPreview']
    red.delete(id)
    logging.info("subject_id = %s", request.form['subject_id'])
    credential['credentialSubject']['id'] = request.form['subject_id']
    try :
        (status, passbase_key, c) = get_passbase_db(request.form['subject_id'])
    except :
        logging.error("Over18 check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase', data)
        return jsonify ('Over18 check has not been done'),404

    if status != "approved" :
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not approved")
                        })
        red.publish('passbase', data)
        return jsonify('not approved'), 404

    identity = get_identity(passbase_key, mode)
    if not identity :
        logging.warning("Identity does not exist")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identity does not exist")
                        })
        red.publish('passbase', data)
        return (jsonify('Identity does not exist'))

    if identity['metadata']['did'] != request.form['subject_id'] :
        logging.warning("wrong wallet")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Wrong wallet")
                        })
        red.publish('passbase', data)
        return (jsonify('wrong wallet'))

    birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
    current_date = datetime.now()
    date1 = datetime.strptime(birthDate,'%Y-%m-%d') + timedelta(weeks=18*52)
    if (current_date > date1) :
        credential['credentialSubject']['id'] = request.form['subject_id']
    else :
        logging.warning("below 18")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Below 18")
                        })
        red.publish('passbase', data)
        return jsonify('below 18')

    didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": vm
        }
    signed_credential =  await didkit.issue_credential(
            json.dumps(credential),
            didkit_options.__str__().replace("'", '"'),
            key
    )
        
    # send event to client agent to go forward
    data = json.dumps({
                    'id' : id,
                    'check' : 'success',
                        })
    red.publish('passbase', data)
    return jsonify(signed_credential)


async def passbase_endpoint_idcard(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/Kyc.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = "did:..."
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z"
        }
        red.set(id, json.dumps(credentialOffer))
        return jsonify(credentialOffer)

    try : 
        credentialOffer = json.loads(red.get(id).decode())
    except :
        logging.error("red get id error, or request time out ")
        return jsonify ('request time out'),408
    credential =  credentialOffer['credentialPreview']
    red.delete(id)
    logging.info("subject_id = %s", request.form['subject_id'])
    credential['credentialSubject']['id'] = request.form['subject_id']
    try :
        (status, passbase_key, c) = get_passbase_db(request.form['subject_id'])
    except :
        logging.error("IDcard check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('ID card check has not been done'),404

    if status != "approved" :
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not approved")
                        })
        red.publish('passbase', data)
        return jsonify('not approved'), 404

    identity = get_identity(passbase_key, mode)
    if not identity :
        logging.warning("Identity does not exist")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identity does not exist")
                        })
        red.publish('passbase', data)
        return (jsonify('Identity does not exist'))

    if identity['metadata']['did'] != request.form['subject_id'] :
        logging.warning("wrong wallet")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Wrong wallet")
                        })
        red.publish('passbase', data)
        return (jsonify('wrong wallet'))

    credential['credentialSubject']['birthPlace'] = identity['resources'][0]['datapoints']['place_of_birth']
    credential['credentialSubject']['givenName'] = identity['owner']['first_name']
    credential['credentialSubject']['familyName'] = identity['owner']['last_name']
    credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints']['sex']
    credential['credentialSubject']['authority'] = identity['resources'][0]['datapoints'].get('authority', "Unknown")
    credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints'].get('nationality', "Unkonwn")
    credential['credentialSubject']['addressCountry'] = identity['resources'][0]['datapoints'].get('mrtd_issuing_country', "Unknown")
    credential['credentialSubject']['expiryDate'] = identity['resources'][0]['datapoints'].get('date_of_expiry', "Unknown")
    credential['credentialSubject']['issueDate'] = identity['resources'][0]['datapoints'].get('date_of_issue', "Unknown")
    didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": vm
        }
    signed_credential =  await didkit.issue_credential(
            json.dumps(credential),
            didkit_options.__str__().replace("'", '"'),
            key
    )
        
    # send event to client agent to go forward
    data = json.dumps({
                    'id' : id,
                    'check' : 'success',
                        })
    red.publish('passbase', data)
    return jsonify(signed_credential)


def passbase_back():
    result = request.args['followup']
    logging.info('back result = %s', result)
    logging.info('back message = %s', request.args.get('message', 'No message'))
    if result == 'failed' :
        message = """ <h2>""" + _("Sorry !") + """<br><br>""" + request.args['message'] + """</h2>"""  
    else :
        message  = """ <h2>""" + _("Congrats !") + """<br><br>""" + _("Your credential has been signed and transfered to your wallet") + """</h2>"""
    html_string = """
        <!DOCTYPE html>
        <html>
        <body class="h-screen w-screen flex">
        <center>
        """ + message + """
        <br><br><br>
        <form action="https://playground.talao.co" method="GET" >
        <button  type"submit" >Playground</button></form>
        </center>
        </body>
        </html>"""
    return render_template_string(html_string)


# server event push for user agent EventSource
def passbase_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('passbase')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()  
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)



