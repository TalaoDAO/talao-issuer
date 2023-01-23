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
import hashlib
from datetime import datetime
import didkit
from datetime import datetime, timedelta
import sqlite3

EXPIRATION_DELAY = timedelta(weeks=52)
LIVENESS_DELAY = timedelta(weeks=2)
ACCESS_TOKEN_LIFE = 180

logging.basicConfig(level=logging.INFO)

key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
#issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"
#issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"

od_liveness = json.loads(open("./credential_manifest/liveness_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_over18 = json.loads(open("./credential_manifest/over18_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_over13 = json.loads(open("./credential_manifest/over13_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_agerange = json.loads(open("./credential_manifest/agerange_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_idcard = json.loads(open("./credential_manifest/idcard_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_linkedincard = json.loads(open("./credential_manifest/linkedincard_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_email = json.loads(open("./credential_manifest/email_credential_manifest.json", 'r').read())['output_descriptors'][0]
#od_phone = json.loads(open("./credential_manifest/phone_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_gender = json.loads(open("./credential_manifest/gender_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_nationality = json.loads(open("./credential_manifest/nationality_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_passportnumber = json.loads(open("./credential_manifest/passportnumber_credential_manifest.json", 'r').read())['output_descriptors'][0]
od_verifiableid = json.loads(open("./credential_manifest/verifiableid_credential_manifest.json", 'r').read())['output_descriptors'][0]


#id_tezotopia_membershipcard = json.loads(open("./credential_manifest/tezotopia_membershipcard_credential_manifest.json", 'r').read())['presentation_definition']['input_descriptors']



credential_manifest =  {
    "id":"Identity_cards",
    "issuer":{
        "id":"uuid:0001",
        "name":"Altme issuer"
    },
    "output_descriptors":list()
}

credential_manifest["output_descriptors"].append(od_over18)
credential_manifest["output_descriptors"].append(od_over13)
credential_manifest["output_descriptors"].append(od_agerange)
credential_manifest["output_descriptors"].append(od_idcard)
credential_manifest["output_descriptors"].append(od_linkedincard)
credential_manifest["output_descriptors"].append(od_liveness)
credential_manifest["output_descriptors"].append(od_gender)
credential_manifest["output_descriptors"].append(od_email)
credential_manifest["output_descriptors"].append(od_nationality)
#credential_manifest["output_descriptors"].append(od_phone)
credential_manifest["output_descriptors"].append(od_passportnumber)
credential_manifest["output_descriptors"].append(od_verifiableid)


#credential_manifest["presentation_definition"]["input_descriptors"].append(id_tezotopia_membershipcard)


def get_passbase_status_from_key(key) :
    """
    return the last one
    """
    conn = sqlite3.connect('passbase_check.db')
    c = conn.cursor()
    data = { "key" : key}
    c.execute("SELECT status created FROM webhook WHERE key = :key", data)
    check = c.fetchall()
    logging.info("check = %s", check)
    conn.close()
    if len(check) == 1 :
        return check[0][0]
    try :
        return check[-1][0]
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
    conn.close()
    if len(check) == 1 :
        return check[0]
    try :
        return check[-1]
    except :
        logging.warning("no DID found for that key")
        return None
      
      
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


# token endpoint /token
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
    
    if grant_type != 'urn:ietf:params:oauth:grant-type:pre-authorized_code'  :
        logging.warning('grant type  or api key is incorrect')
        endpoint_response= {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if x_api_key not in ['99999-99999-99999', mode.altme_wallet_token] :
        logging.warning('api key is incorrect')
        endpoint_response= {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if get_passbase_status_from_key(pre_authorized_code) != "approved" :
        logging.warning('check is still pending or declined')
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

    try :
        passbase_did =  get_passbase_did_from_key(data['passbase_key'])[0]
    except :
        logging.info("passbase key = %s", passbase_did)
        logging.warning("That key is not found in the database")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "key_does_not_match", "error_description" : "Passbase key not found"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    if passbase_did != wallet_did :
        logging.info("passbase key = %s", passbase_did)
        logging.info("wallet DID = %s", wallet_did)
        logging.warning("wallet key does not match passbase ID key")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "key_does_not_match", "error_description" : "The wallet key does not match the KYC"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    result = json.loads(await didkit.verify_presentation(did_authn, '{}'))['errors']
    if result :
        logging.warning("Verify presentation  error %s", result)
        #headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        #endpoint_response = {"error" : "invalid_proof", "error_description" : "The proof check fails"}
        # return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
   
    if wallet_request['type'] == "Over13" :
        credential = json.loads(open("./verifiable_credentials/Over13.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] = data['passbase_key']
        credential['credentialSubject']['kycProvider'] = "Passbase"
        credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"

        try :
            birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
        except :
            logging.warning("Under 13")
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_over18", "error_description" : "Birthdate not available"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
        current_date = datetime.now()
        date1 = datetime.strptime(birthDate,'%Y-%m-%d') + timedelta(weeks=13*52)
        if not (current_date > date1) :
            logging.warning("user is under 13")
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_over18", "error_description" : "User is under 13 age old"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    elif wallet_request['type'] == "Over18" :
        credential = json.loads(open("./verifiable_credentials/Over18.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] = data['passbase_key']
        credential['credentialSubject']['kycProvider'] = "Passbase"
        credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
        try :
            birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
        except :
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_over18", "error_description" : "Birthdate not available"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
        current_date = datetime.now()
        date1 = datetime.strptime(birthDate,'%Y-%m-%d') + timedelta(weeks=18*52)
        if not (current_date > date1) :
            logging.warning("User is under 18")
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_over18", "error_description" : "User is under 18 age old"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)  

    elif wallet_request['type'] == "Liveness" :
        credential = json.loads(open("./verifiable_credentials/Liveness.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + LIVENESS_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] = data['passbase_key']
        credential['credentialSubject']['kycProvider'] = "Passbase"
        credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
 
    elif wallet_request['type'] == "Gender" :
        credential = json.loads(open("./verifiable_credentials/Gender.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] = data['passbase_key']
        credential['credentialSubject']['kycProvider'] = "Passbase"
        credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
        try :
            credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints']['sex']
        except :
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_over18", "error_description" : "Gender data not available"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    elif wallet_request['type'] == "Nationality" :
        credential = json.loads(open("./verifiable_credentials/Nationality.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] = data['passbase_key']
        credential['credentialSubject']['kycProvider'] = "Passbase"
        credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
        try :
            credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints']['document_origin_country']
        except :
            try :
                credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints']['country']
            except :
                headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
                endpoint_response = {"error" : "invalid_over18", "error_description" : "Nationality not available"}
                return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    elif wallet_request['type'] == "PassportNumber" :
        credential = json.loads(open("./verifiable_credentials/PassportNumber.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] = data['passbase_key']
        credential['credentialSubject']['kycProvider'] = "Passbase"
        credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
        try :
            document_number = identity['resources'][0]['datapoints']['raw_mrz_string']
            credential['credentialSubject']['passportNumber'] = hashlib.sha256(document_number.encode()).hexdigest()
        except :
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_over18", "error_description" : "Nationality not available"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    elif wallet_request['type'] == "EmailPass" :
        credential = json.loads(open("./verifiable_credentials/EmailPass.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['email'] = identity['owner']['email']

    elif wallet_request['type'] == "LinkedinCard" :
        credential = json.loads(open("./verifiable_credentials/LinkedinCard.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['yearOfBirth'] = identity['resources'][0]['datapoints'].get('date_of_birth', "Not indicated")[:4]
        credential['credentialSubject']['familyName'] = identity['owner']['first_name']
        credential['credentialSubject']['givenName'] = identity['owner']['last_name']
        credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints'].get('document_origin_country', "Not indicated")
        """
        credential['evidence'][0]['kycId'] = data['passbase_key']
        try :
            credential['evidence'][0]['evidenceDocument'] = identity['resources'][0]['type'].replace('_', ' ')
        except :
            credential['evidence'][0]['evidenceDocument'] = "Not indicated"
        """
    elif wallet_request['type'] == "VerifiableId" :
        credential = json.loads(open("./verifiable_credentials/VerifiableId.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['validFrom'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['issued'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['placeOfBirth'] = identity['resources'][0]['datapoints'].get('place_of_birth', "Not indicated")
        credential['credentialSubject']['dateOfBirth'] = identity['resources'][0]['datapoints'].get('date_of_birth', "Not indicated")
        credential['credentialSubject']['familyName'] = identity['owner']['first_name']
        credential['credentialSubject']['firstName'] = identity['owner']['last_name']
        credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints'].get('sex', "Not indicated")
        credential['credentialSubject']['personalIdentifier'] = identity['resources'][0]['datapoints']['raw_mrz_string']
        credential['evidence'][0]['kycId'] = data['passbase_key']
        try :
            credential['evidence'][0]['evidenceDocument'] = identity['resources'][0]['type'].replace('_', ' ')
        except :
            credential['evidence'][0]['evidenceDocument'] = "Not indicated"

    elif wallet_request['type'] == "AgeRange" :
        credential = json.loads(open("./verifiable_credentials/AgeRange.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] = data['passbase_key']
        credential['credentialSubject']['kycProvider'] = "Passbase"
        credential['credentialSubject']['kycMethod'] = "https://docs.passbase.com/"
        try :
            birthDate = identity['resources'][0]['datapoints']['date_of_birth'] # "1970-01-01"
        except :
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_over18", "error_description" : "Birthdate not available"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
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
        if datetime.now() < date18 :
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
  

