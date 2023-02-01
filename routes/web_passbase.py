import sqlite3
from flask import jsonify, request, render_template, Response, redirect
import json
from datetime import timedelta, datetime
import didkit
import uuid
from urllib.parse import urlencode
from datetime import datetime
import logging
from flask_babel import Babel, _
import sqlite3
import requests
from components import message
import hashlib

logging.basicConfig(level=logging.INFO)

OFFER_DELAY = timedelta(seconds= 10*60)
EXPIRATION_DELAY = timedelta(weeks=52)
LIVENESS_DELAY = timedelta(weeks=2)

approval_text = """Hello,<br>
<br>Well done, your <strong>KYC is complete</strong> !<br>
<br>You can now add <strong>6 digital credentials</strong> in your <strong>Altme Wallet</strong> :<br><br>
<li><strong>Over 18 Proof</strong> : to prove your email ownership to Web 3 Apps.</li><br>
<li><strong>Age Range Proof</strong> : to prove your Age Range to Web 3 Apps (Gaming, DeFi...).</li><br>
<li><strong>Email Proof</strong> : To access Web 3 services or claim benefits : Membership card, Loyalty card, Rewards…</li><br>
<li><strong>Nationality Proof</strong> : to prove your Nationality without revealing any other information about you. It can be used in a user survey, etc.</li><br>
<li><strong>Identity card</strong> : This digital identity card contains the same information as your physical ID card.You can use it in Web 3 for a KYC check for example.</li><br>
<br>
Regards,<br>
Altme team - <a href='https://app.altme.io/app/download'>Open your wallet</a> 
"""

key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
#issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"
#vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"

 
def init_app(app,red, mode) :
    app.add_url_rule('/over18',  view_func=over18, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/over13',  view_func=over13, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/liveness',  view_func=liveness, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/kyc',  view_func=kyc, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/nationality',  view_func=nationality, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/agerange',  view_func=agerange, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/gender',  view_func=gender, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/passportnumber',  view_func=pass_number, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/pass_number',  view_func=pass_number, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/verifiableid',  view_func=verifiableid, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/linkedincard',  view_func=linkedincard, methods = ['GET'], defaults={'mode' : mode})


    app.add_url_rule('/vc',  view_func=vc, methods = ['GET'], defaults={'mode' : mode})

    app.add_url_rule('/passbase/webhook',  view_func=passbase_webhook, methods = ['POST'], defaults={ 'mode' : mode})
    app.add_url_rule('/wallet/webhook',  view_func=wallet_webhook, methods = ['POST'],  defaults={ 'mode' : mode})
    app.add_url_rule('/passbase/check/<did>',  view_func=passbase_check, methods = ['GET'],  defaults={ 'mode' : mode})
    
    app.add_url_rule('/passbase/endpoint/over13/<id>',  view_func=passbase_endpoint_over13, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/over18/<id>',  view_func=passbase_endpoint_over18, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/liveness/<id>',  view_func=passbase_endpoint_liveness, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/kyc/<id>',  view_func=passbase_endpoint_kyc, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/agerange/<id>',  view_func=passbase_endpoint_age_range, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/nationality/<id>',  view_func=passbase_endpoint_nationality, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/gender/<id>',  view_func=passbase_endpoint_gender, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/passportnumber/<id>',  view_func=passbase_endpoint_passport_number, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/verifiableid/<id>',  view_func=passbase_endpoint_verifiable_id, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/passbase/endpoint/linkedincard/<id>',  view_func=passbase_endpoint_linkedin_card, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})


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


def get_passbase_data_from_did(did) :
    """
    return the last one
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


def get_passbase_did_from_key(key) :
    """
    return the last one
    
    """
    conn = sqlite3.connect('passbase_check.db')
    c = conn.cursor()
    data = { "key" : key}
    c.execute("SELECT did FROM webhook WHERE key = :key", data)
    check = c.fetchall()
    logging.info("check = %s", check)
    conn.close()
    if len(check) == 1 :
        return check[0]
    try :
        return check[-1]
    except :
        return None


def passbase_check(did, mode) :
    """
    API for wallet
    return approved, declined, notdone, pending
    last check
    # curl http://10.188.95.48:5000/passbase/check/did:key:z6Mkvu9HqJoNJsFPrfWEnTvy5tYh3uTgjPz3iqMPiUzzoWMb  -H "Accept: application/json"   -H "Authorization: Bearer mytoken"

    """
    try :
        access_token = request.headers["Authorization"].split()[1]
    except :
        logging.warning('invalid request')
        endpoint_response= {"error": "invalid_request"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    if access_token not in ['mytoken',  mode.altme_passbase_check] :
        logging.warning('api key is incorrect')
        endpoint_response= {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    check = get_passbase_data_from_did(did) 
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
    return redirect ('/vc?credential=over18')
def over13(mode) :
    return redirect ('/vc?credential=over13')
def liveness(mode) :
    return redirect ('/vc?credential=liveness')
def kyc(mode) :
    return redirect ('/vc?credential=kyc')
def agerange(mode) :
    return redirect ('/vc?credential=agerange')
def nationality(mode) :
    return redirect ('/vc?credential=nationality')
def gender(mode) :
    return redirect ('/vc?credential=gender')
def pass_number(mode) :
    return redirect ('/vc?credential=passportnumber')
def verifiableid(mode) :
    return redirect ('/vc?credential=verifiableid')
def linkedincard(mode) :
    return redirect ('/vc?credential=linkedincard')


def vc(mode) :
    id = str(uuid.uuid1())
    credential = request.args['credential']
    url = mode.server + "passbase/endpoint/" + credential + '/' + id +'?issuer=' + issuer_did
    deeplink_talao = mode.deeplink_talao + 'app/download?' + urlencode({'uri' : url })
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri' : url })
    return render_template('/passbase/' + credential + '.html',
                                url=url,
                                deeplink_altme=deeplink_altme,
                                deeplink_talao=deeplink_talao,
                                id=id
                                )

"""
API for wallet

For ALTME

curl --location --request POST 'https://issuer.talao.co/wallet/webhook' \
--header 'Content-Type: application/json' \
--data-raw '{"event": "VERIFICATION_COMPLETED","key": "-.......", "status": "pending", "DID" : "did:key:...."}'
--header "Authorization: Bearer mytoken"

curl --location --request POST 'http://10.188.95.48:5000/wallet/webhook' --header 'Content-Type: application/json' --data-raw '{"identityAccessKey": "22a363e6-2f93-4dd3-9ac8-6cba5a046acd", "DID" : "did:key:2"}' --header "Authorization: Bearer mytoken"

curl --location --request POST 'https://issuer.talao.co/wallet/webhook' --header 'Content-Type: application/json' --data-raw '{"identityAccessKey": "22a363e6-2f93-4dd3-9ac8-6cba5a046acd", "DID" : "did:key:...."}' --header "Authorization: Bearer mytoken"

no email is sent
"""
def wallet_webhook(mode) :
    try :
        access_token = request.headers["Authorization"].split()[1]
        logging.info("access token = %s", access_token)    
    except :
        logging.warning('invalid request')
        endpoint_response= {"error": "invalid_request"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    if access_token not in [ "mytoken",  mode.altme_wallet_webhook] :
        endpoint_response= {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    webhook = request.get_json()
    logging.info("wallet webhook has received an event = %s", webhook)
    add_passbase_db("",
                "pending",
                webhook['DID'],
                webhook['identityAccessKey'],
                round(datetime.now().timestamp()) )
    return jsonify("ok"), 200


"""
For TALAO wallet and ALtME

curl --location --request POST 'http://10.188.95.48:5000/passbase/webhook' --header 'Content-Type: application/json' --data-raw '{"event": "VERIFICATION_REVIEWED","key": "22a363e6-2f93-4dd3-9ac8-6cba5a046acd", "status": "approved", "created" : 1582628712}'


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
        return jsonify('Event received')
    
    # get identity data from Passbase and set the issuer local database with minimum data
    identity = get_identity(webhook['key'], mode)
    if not identity :
        logging.error("probleme d acces API")
        return jsonify("probleme d acces API")
    
    email = identity['owner'].get('email', "Not indicated")
    
    try :
        did = get_passbase_did_from_key(webhook['key'])[0]
    except :
        logging.error("Key does not exist in local DB")
        return jsonify('Key not stored in DB')

    add_passbase_db(email,
                webhook['status'],
                did,
                webhook['key'],
                round(datetime.now().timestamp())
                )
    # send notification by email if email exists
    if email :
        if webhook['status' ] == "approved" :
            try :
                message.message_html("Congratulations : Altme KYC is complete !", email, approval_text, mode)
                logging.info("Approved, email sent to %s", email)
            except :
                logging.error("failed to send message")
            return jsonify('ok, notification sent')
        else :
            link_text = "Sorry ! \nThe authentication failed.\nProbably the identity documents are not acceptable.\nLet's try again with another type of document."
            message.message(_("AltMe wallet identity credential"), email, link_text, mode)
            link_text = "The authentication failed.\nProbably the identity documents are not acceptable for " + email
            message.message(_("AltMe wallet identity credential"), "thierry@altme.io", link_text, mode)
            message.message(_("AltMe wallet identity credential"), "hugo@altme.io", link_text, mode)
            logging.info("email sent to %s", email)
            logging.warning('Identification not approved')
            return jsonify("Event received")

    return jsonify('Event received')


async def passbase_endpoint_over13(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/Over13.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential_manifest = json.loads(open("./credential_manifest/over13_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = "did:wallet"
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
    credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
    credential['credentialSubject']['kycProvider'] = "Passbase"

    #on recupere la cle passbase depuis notre base locale
    try :
        (status, passbase_key, created) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("Over13 check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase', data)
        return jsonify ('KYC has not been done'),404

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
    credential['credentialSubject']['kycId'] = passbase_key
    try :
        birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
    except :  
        logging.error("Birthdate not available")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Birth date not available")
                        })
        red.publish('passbase', data)
        return jsonify ('Birth date not available'),404

    current_date = datetime.now()
    date1 = datetime.strptime(birthDate,'%Y-%m-%d') + timedelta(weeks=13*52)
    if (current_date > date1) :
        credential['credentialSubject']['id'] = request.form['subject_id']
    else :
        logging.warning("below 13")
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

async def passbase_endpoint_over18(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/Over18.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential_manifest = json.loads(open("./credential_manifest/over18_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = "did:wallet"
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
    credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
    credential['credentialSubject']['kycProvider'] = "Passbase"

    #on recupere la cle passbase depuis notre base locale
    try :
        (status, passbase_key, created) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("Over18 check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase', data)
        return jsonify ('KYC has not been done'),404

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
    credential['credentialSubject']['kycId'] = passbase_key
    try :
        birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
    except :  
        logging.error("Birthdate not available")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Birth date not available")
                        })
        red.publish('passbase', data)
        return jsonify ('Birth date not available'),404

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

async def passbase_endpoint_kyc(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/IdCard.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['credentialSubject']['id'] = "did:wallet"
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential_manifest = json.loads(open("./credential_manifest/idcard_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
    credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
    credential['credentialSubject']['kycProvider'] = "Passbase"

    try :
        (status, passbase_key, c) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("IDcard check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('KYC has not been done'),404

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
    credential['credentialSubject']['kycId'] = passbase_key
    credential['credentialSubject']['birthPlace'] = identity['resources'][0]['datapoints'].get('place_of_birth', 'Not indicated')
    credential['credentialSubject']['birthDate'] = identity['resources'][0]['datapoints'].get('date_of_birth', "Not indicated")
    credential['credentialSubject']['givenName'] = identity['owner']['first_name']
    credential['credentialSubject']['familyName'] = identity['owner']['last_name']
    credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints'].get('sex', "Not indicated")
    credential['credentialSubject']['authority'] = identity['resources'][0]['datapoints'].get('authority', "Not indicated")
    credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints'].get('nationality', "Not indicated")
    credential['credentialSubject']['expiryDate'] = identity['resources'][0]['datapoints'].get('date_of_expiry', "Not indicated")
    credential['credentialSubject']['issueDate'] = identity['resources'][0]['datapoints'].get('date_of_issue', "Not indicated")
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


async def passbase_endpoint_verifiable_id(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/VerifiableId.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['issued'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['validFrom'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['credentialSubject']['id'] = "did:wallet"
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential_manifest = json.loads(open("./credential_manifest/verifiableid_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
        (status, passbase_key, c) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("IDcard check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('Your ID check has not been done'),412

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
    credential['credentialSubject']['placeOfBirth'] = identity['resources'][0]['datapoints'].get('place_of_birth', 'Not indicated')
    credential['credentialSubject']['dateOfBirth'] = identity['resources'][0]['datapoints'].get('date_of_birth', "Not indicated")
    credential['credentialSubject']['familyName'] = identity['owner']['first_name']
    credential['credentialSubject']['firstName'] = identity['owner']['last_name']
    credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints'].get('sex', "Not indicated")
    credential['credentialSubject']['personalIdentifier'] = identity['resources'][0]['datapoints'].get('raw_mrz_string', "Not indicated")
    # "personalIdentifier": "IT/DE/1234",
    credential['evidence'][0]['kycId'] = passbase_key
    try :
        credential['evidence'][0]['evidenceDocument'] = identity['resources'][0]['type'].replace('_', ' ')
    except :
        credential['evidence'][0]['evidenceDocument'] = "Not indicated"
   
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


async def passbase_endpoint_linkedin_card(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/LinkedinCard.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['credentialSubject']['id'] = "did:wallet"
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential_manifest = json.loads(open("./credential_manifest/linkedincard_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
        (status, passbase_key, c) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("IDcard check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('Your ID check has not been done'),412

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
    credential['credentialSubject']['yearOfBirth'] = identity['resources'][0]['datapoints'].get('date_of_birth', "Not indicated")[:4]
    credential['credentialSubject']['familyName'] = identity['owner']['first_name']
    credential['credentialSubject']['givenName'] = identity['owner']['last_name']
    credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints'].get('nationality', "Not indicated")
    """
    credential['evidence'][0]['kycId'] = passbase_key
    try :
        credential['evidence'][0]['evidenceDocument'] = identity['resources'][0]['type'].replace('_', ' ')
    except :
        credential['evidence'][0]['evidenceDocument'] = "Not indicated"
    """
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


async def passbase_endpoint_age_range(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/AgeRange.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['credentialSubject']['id'] = "did:wallet"
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential_manifest = json.loads(open("./credential_manifest/agerange_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
    credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
    credential['credentialSubject']['kycProvider'] = "Passbase"

    try :
        (status, passbase_key, c) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("KYC has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('KYC has not been done'),404

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
    
    #age range : "-13" or "14-17” or “18-24”, “25-34”, “35-44”, “45-54”, “55-64”, “65+”.
    credential['credentialSubject']['kycId'] = passbase_key
    try :
        birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
    except :  
        logging.error("Birthdate not available")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Birth date not available")
                        })
        red.publish('passbase', data)
        return jsonify ('Birth date not available'),404

    year = birthDate.split('-')[0]
    month = birthDate.split('-')[1]
    day = birthDate.split('-')[2]
    date13 = datetime(int(year) + 13, int(month), int(day))
    date18 = datetime(int(year) + 18, int(month), int(day))
    date25 = datetime(int(year) + 25, int(month), int(day))
    date35 = datetime(int(year) + 35, int(month), int(day))
    date45 = datetime(int(year) + 45, int(month), int(day))
    date55 = datetime(int(year) + 55, int(month), int(day))
    date65 = datetime(int(year) + 65, int(month), int(day))
    
    if datetime.now() < date13 :
        credential['credentialSubject']['ageRange'] = "-13"
    elif datetime.now() < date18 :
        credential['credentialSubject']['ageRange'] = "14-17"
    elif datetime.now() < date25 :
        credential['credentialSubject']['ageRange'] = "18-24"
    elif datetime.now() < date35 :
        credential['credentialSubject']['ageRange'] = "25-34"
    elif datetime.now() < date45 :
        credential['credentialSubject']['ageRange'] = "35-44"
    elif datetime.now() < date55 :
        credential['credentialSubject']['ageRange'] = "45-54"
    elif datetime.now() < date65 :
        credential['credentialSubject']['ageRange'] = "55-64"
    else :
        credential['credentialSubject']['ageRange'] = "65+"
    
    expiration = datetime.now() + timedelta(weeks=52)
    credential['expirationDate'] = expiration.replace(microsecond=0).isoformat() + "Z"

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


async def passbase_endpoint_nationality(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/Nationality.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['credentialSubject']['id'] = "did:wallet"
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential_manifest = json.loads(open("./credential_manifest/nationality_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
    credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
    credential['credentialSubject']['kycProvider'] = "Passbase"

    try :
        (status, passbase_key, c) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("IDcard check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('KYC has not been done'),404

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

    try :
        credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints']['nationality']
    except :  
        logging.error("Nationality not available")
        data = json.dumps({
                'id' : id,
                'check' : 'failed',
                'message' : _("Nationality not available")
        })
        red.publish('passbase', data)
        return jsonify ('Nationality not available'),404

    credential['credentialSubject']['kycId'] = passbase_key
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

async def passbase_endpoint_passport_number(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/PassportNumber.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['credentialSubject']['id'] = "did:wallet"
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential_manifest = json.loads(open("./credential_manifest/passportnumber_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
    credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
    credential['credentialSubject']['kycProvider'] = "Passbase"

    try :
        (status, passbase_key, c) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("IDcard check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('KYC has not been done'),404

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
    try :
        document_number = identity['resources'][0]['datapoints'].get('raw_mrz_string', "Not indicated")
        credential['credentialSubject']['passportNumber'] = hashlib.sha256(document_number.encode()).hexdigest()
        credential['credentialSubject']['kycId'] = passbase_key
    except :
        logging.error("Passport MRZ not available")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Passport MRZ not available")
                        })
        red.publish('passbase', data)
        return jsonify ('Passport MRZ not available'),404

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

async def passbase_endpoint_gender(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/Gender.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['credentialSubject']['id'] = "did:wallet"
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential_manifest = json.loads(open("./credential_manifest/gender_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
    credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
    credential['credentialSubject']['kycProvider'] = "Passbase"

    try :
        (status, passbase_key, c) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("IDcard check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('KYC has not been done'),404

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

    try :
        credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints']['sex']
    except :  
        logging.error("Gender not available")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Nationality not available")
                        })
        red.publish('passbase', data)
        return jsonify ('Gender not available not available'),404

    credential['credentialSubject']['kycId'] = passbase_key
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

async def passbase_endpoint_liveness(id,red,mode):
    if request.method == 'GET':
        credential = json.loads(open("./verifiable_credentials/Liveness.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + LIVENESS_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['credentialSubject']['id'] = "did:wallet"
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential_manifest = json.loads(open("./credential_manifest/liveness_credential_manifest.json", 'r').read())
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credentialOffer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
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
    credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
    credential['credentialSubject']['kycProvider'] = "Passbase"

    try :
        (status, passbase_key, c) = get_passbase_data_from_did(request.form['subject_id'])
    except :
        logging.error("IDcard check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : _("Identification not done")
                        })
        red.publish('passbase_idcard', data)
        return jsonify ('KYC has not been done'),404

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
    credential['credentialSubject']['kycId'] = passbase_key
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


def passbase_back() :
    if request.args['followup'] == "success" :
        message = _('Great ! you have now your credential.')
    else :
        message = _('Sorry ! there is a server problem, try again later.')
    return render_template('passbase/passbase_end.html', message=message)


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



