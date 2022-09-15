"""
def get_version() -> str: ...
def generate_ed25519_key() -> str: ...
def key_to_did(method_pattern: str, jwk: str) -> str: ...
async def key_to_verification_method(method_pattern: str, jwk: str) -> str: ...
async def issue_credential(credential: str, proof_options: str, key: str) -> str: ...
async def verify_credential(credential: str, proof_options: str) -> str: ...
async def issue_presentation(presentation: str, proof_options: str, key: str) -> str: ...
async def verify_presentation(presentation: str, proof_options: str) -> str: ...
async def resolve_did(did: str, input_metadata: str) -> str: ...
async def dereference_did_url(did_url: str, input_metadata: str) -> str: ...
async def did_auth(did: str, options: str, key: str) -> str: ...
"""

from flask import jsonify, request,Response, jsonify
from flask import Response, jsonify
import requests
import json
import uuid
import logging
from datetime import datetime
import didkit
from datetime import datetime, timedelta
import sqlite3

EXPIRATION_DELAY = timedelta(weeks=52)
LIVENESS_DELAY = timedelta(weeks=2)
ACCESS_TOKEN_LIFE = 360

logging.basicConfig(level=logging.INFO)

key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"
issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"

od_liveness = json.loads(open("./credential_manifest/liveness_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_over18 = json.loads(open("./credential_manifest/over18_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_agerange = json.loads(open("./credential_manifest/agerange_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_idcard = json.loads(open("./credential_manifest/idcard_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_email = json.loads(open("./credential_manifest/email_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_phone = json.loads(open("./credential_manifest/phone_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_gender = json.loads(open("./credential_manifest/gender_credential_manifest.json", 'r').read())['output_descriptors'][0]
credential_manifest =  {
    "id":"Identity_cards",
    "issuer":{
        "id":"0000",
        "name":"Altme issuer"
    },
    "output_descriptors":list()
}     
credential_manifest["output_descriptors"].append(od_over18)
credential_manifest["output_descriptors"].append(od_agerange)
credential_manifest["output_descriptors"].append(od_idcard)
credential_manifest["output_descriptors"].append(od_liveness)
credential_manifest["output_descriptors"].append(od_gender)
credential_manifest["output_descriptors"].append(od_email)


def get_passbase_did_from_key(key) :
    """
    return the last one    
    """
    conn = sqlite3.connect('passbase_check.db')
    c = conn.cursor()
    data = { "key" : key}
    c.execute("SELECT did FROM webhook WHERE key = :key", data)
    check = c.fetchall()
    conn.close()
    if len(check) == 1 :
        return check[0]
    try :
        return check[-1]
    except :
        logging.warning("no DID found")
      
      
def init_app(app,red, mode) :
    app.add_url_rule('/token',  view_func=wallet_token, methods = ['GET', 'POST'], defaults={"red" : red, 'mode' : mode})
    app.add_url_rule('/credential',  view_func=credential, methods = ['GET', 'POST'], defaults={"red" : red})
    app.add_url_rule('/.well-known/openid-configuration', view_func=openid_configuration, methods=['GET'], defaults={'mode' : mode})
    # https://issuer.talao.co/.well-known/openid-configuration
    # https://server.com/.well-known/openid-configuration
    return   


def get_identity(passbase_key, mode) :
    url = "https://api.passbase.com/verification/v1/identities/" + passbase_key
    logging.info("API call url = %s", url)
    headers = {
        'accept' : 'application/json',
        'X-API-KEY' : mode.passbase
    }
    try :
        r = requests.get(url, headers=headers)
    except :
        logging.error("Passbase connexion problem")
        return None
    logging.info("status code = %s", r.status_code)
    if not 199<r.status_code<300 :
        logging.error("API call rejected %s", r.status_code)
        return None
    return  r.json()


def openid_configuration(mode):
    oidc = {
        "issuer": mode.server,
        "token_endpoint": mode.server + 'token',
        "credential_endpoint": mode.server + 'credential',
        "credential_manifest" : credential_manifest,
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic"
        ]
    }
    return jsonify(oidc)


# token endpoint
async def wallet_token(red, mode) :
    try :
        x_api_key = request.headers['X-API-KEY']
        grant_type =  request.form['grant_type']
        pre_authorized_code = request.form['pre-authorized_code']    
    except :
        logging.warning('invalid request')
        endpoint_response= {"error": "invalid_request"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    if grant_type != 'urn:ietf:params:oauth:grant-type:pre-authorized_code' or x_api_key != '99999-99999-99999':
        logging.warning('grant type  or api key is incorrect')
        endpoint_response= {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    identity = get_identity(pre_authorized_code, mode)
    if not identity :
        logging.warning('KYC not completed or ID key error' )
        endpoint_response= {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    # token response
    access_token = str(uuid.uuid1())
    c_nonce = str(uuid.uuid1())
    endpoint_response = {
                        "access_token" : access_token,
                        "token_type" : "Bearer",
                        "expires_in": ACCESS_TOKEN_LIFE,
                        "c_nonce" : c_nonce,
                        "c_nonce_expires_in" : ACCESS_TOKEN_LIFE
                        }
    red.setex(access_token, 
            ACCESS_TOKEN_LIFE,
            json.dumps({"identity" : identity,
                "c_nonce" : c_nonce,
                "passbase_key" : pre_authorized_code}))

    headers = {
        "Cache-Control" : "no-store",
        "Pragma" : "no-cache",
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# credential endpoint
async def credential(red) :

    try : 
        access_token = request.headers["Authorization"].split()[1] 
        wallet_request = request.get_json()
        wallet_did = wallet_request['did']
        did_authn = wallet_request['proof']["vp"]
    except :
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "The request is not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    try :
        data = json.loads(red.get(access_token).decode())
        identity = data['identity']
        c_nonce = data['c_nonce']
    except :
        logging.warning("Invalid access token")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_access_token", "error_description" : "Access token invalid or expired"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if  c_nonce != json.loads(did_authn)['proof']['challenge'] :
        logging.warning("Proof challenge does not match")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "Challeng does not match"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    passbase_key =  get_passbase_did_from_key(data['passbase_key'])[0]
    if passbase_key != wallet_did :
        logging.info("passbase key = %s", passbase_key)
        logging.info("wallet DID = %s", wallet_did)
        logging.warning("wallet key does not match passbase ID key")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "key_does_not_match", "error_description" : "The wallet key does not match the KYC"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    result = json.loads(await didkit.verify_presentation(did_authn, '{}'))['errors']
    if result :
        logging.warning("Proof of key errorn %s", result)
        #headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        #endpoint_response = {"error" : "invalid_proof", "error_description" : "The proof check fails"}
        # return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
   
    if wallet_request['type'] == "Over18" :
        credential = json.loads(open("./verifiable_credentials/Over18.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
        current_date = datetime.now()
        date1 = datetime.strptime(birthDate,'%Y-%m-%d') + timedelta(weeks=18*52)
        if not (current_date > date1) :
            logging.warning("Under 18")
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_over18", "error_description" : "User is under 18 age old"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    elif wallet_request['type'] == "Liveness" :
        credential = json.loads(open("./verifiable_credentials/Over18.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + LIVENESS_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
           
    elif wallet_request['type'] == "Gender" :
        credential = json.loads(open("./verifiable_credentials/Gender.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints'].get('sex', "Unknown")

    elif wallet_request['type'] == "Nationality" :
        credential = json.loads(open("./verifiable_credentials/Nationality.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints'].get('mrtd_issuing_country', "Unknown")

    elif wallet_request['type'] == "EmailPass" :
        credential = json.loads(open("./verifiable_credentials/EmailPass.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['email'] = identity['owner']['email']

    elif wallet_request['type'] == "IdCard" :
        credential = json.loads(open("./verifiable_credentials/IdCard.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['birthPlace'] = identity['resources'][0]['datapoints']['place_of_birth']
        credential['credentialSubject']['birthDate'] = identity['resources'][0]['datapoints']['date_of_birth']
        credential['credentialSubject']['givenName'] = identity['owner']['first_name']
        credential['credentialSubject']['familyName'] = identity['owner']['last_name']
        credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints']['sex']
        credential['credentialSubject']['authority'] = identity['resources'][0]['datapoints'].get('authority', "Unknown")
        credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints'].get('nationality', "Unkonwn")
        credential['credentialSubject']['addressCountry'] = identity['resources'][0]['datapoints'].get('mrtd_issuing_country', "Unknown")
        credential['credentialSubject']['expiryDate'] = identity['resources'][0]['datapoints'].get('date_of_expiry', "Unknown")
        credential['credentialSubject']['issueDate'] = identity['resources'][0]['datapoints'].get('date_of_issue', "Unknown")

    elif wallet_request['type'] == "AgeRange" :
        credential = json.loads(open("./verifiable_credentials/AgeRange.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
        year = birthDate.split('-')[0]
        month = birthDate.split('-')[1]
        day = birthDate.split('-')[2]
        
        date18 = datetime(int(year) + 18, int(month), int(day))
        date24 = datetime(int(year) + 24, int(month), int(day))
        date34 = datetime(int(year) + 34, int(month), int(day))
        date44 = datetime(int(year) + 44, int(month), int(day))
        date54 = datetime(int(year) + 54, int(month), int(day))
        date64 = datetime(int(year) + 64, int(month), int(day))
        if datetime.now() < date18 :
            credential['credentialSubject']['ageRange'] = "-18"
            expiration = date18
        elif datetime.now() < date24 :
            credential['credentialSubject']['ageRange'] = "18-24"
            expiration = date24
        elif datetime.now() < date34 :
            credential['credentialSubject']['ageRange'] = "25-34"
            expiration = date34
        elif datetime.now() < date44 :
            credential['credentialSubject']['ageRange'] = "35-44"
            expiration = date44
        elif datetime.now() < date54 :
            credential['credentialSubject']['ageRange'] = "45-54"
            expiration = date54
        elif datetime.now() < date64 :
            credential['credentialSubject']['ageRange'] = "55-64"
            expiration = date64
        else :
            credential['credentialSubject']['ageRange'] = "65+"
            expiration = datetime.now() + timedelta(weeks=5*52)
        
        expiration = datetime.now() + timedelta(weeks=52)
        credential['expirationDate'] = expiration.replace(microsecond=0).isoformat() + "Z"
    else :
        logging.warning("credential requested not found")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "The credential requested is not supported"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
    }
    credential_signed =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
    data = {
        "format": "ldp_vc",
        "credential" : credential_signed
    }
    return jsonify(data)
  

