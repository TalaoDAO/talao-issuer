
from yoti_python_sdk.http import SignedRequest
from flask import jsonify, Response, request
import json
import requests
import base64
import logging
import uuid
from datetime import datetime, timedelta
import didkit
import hashlib
logging.basicConfig(level=logging.INFO)

EXPIRATION_DELAY = timedelta(weeks=52)
LIVENESS_DELAY = timedelta(weeks=2)
ACCESS_TOKEN_LIFE = 180

key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"
issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"

PATHS = {
    "AGE": '/age',
    "LIVENESS": '/antispoofing',
    "AGE_LIVENESS": '/age-antispoofing',
}

def init_app(app,red, mode) :
    app.add_url_rule('/ai/over13',  view_func=ai_over13, methods = ['POST'], defaults ={'mode' : mode})
    app.add_url_rule('/ai/over18',  view_func=ai_over18, methods = ['POST'], defaults ={'mode' : mode})
    return

def execute(request):
    response = requests.request(
        url=request.url, img=request.img, headers=request.headers, method=request.method)
    return response.content

def generate_session(encoded_string, mode):
    img = {"img" : encoded_string.decode("utf-8")}
    payload_string = json.dumps(img).encode()

    signed_request = (
        SignedRequest
        .builder()
        .with_pem_file(mode.yoti_pem_file)
        .with_base_url("https://api.yoti.com/ai/v1")
        .with_endpoint(PATHS['AGE'])
        .with_http_method("POST")
        .with_header("X-Yoti-Auth-Id", mode.yoti)
        .with_payload(payload_string)
        .build()
    )
	# get Yoti response
    response = signed_request.execute()
    response_payload = json.loads(response.text)
    return response_payload

def sha256 (x) :
    return hashlib.sha256(x).digest().hex()

# credential endpoint
async def ai_over13(mode) :
    try : 
        x_api_key = request.headers['X-API-KEY']
        wallet_request = request.get_json()    
    except :
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "request is not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    try :  
        wallet_did = wallet_request['did']
        did_authn = wallet_request["vp"]
        encoded_string = wallet_request["base64_encoded_string"].encode()
    except :
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "data sent are not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if  x_api_key != mode.altme_ai_token :
        logging.warning('api key is incorrect')
        endpoint_response= {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if  sha256(encoded_string) != json.loads(did_authn)['proof']['challenge'] :
        logging.warning("Proof challenge does not match")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "Challeng does not match"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    result = json.loads(await didkit.verify_presentation(did_authn, '{}'))['errors']
    if result :
        logging.warning("Verify presentation  error %s", result)
        #headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        #endpoint_response = {"error" : "invalid_proof", "error_description" : "The proof check fails"}
        # return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
   
    result = generate_session(encoded_string, mode)
    try :
        age = int(result['age'])
    except :
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : json.dumps(result)}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
      
    logging.info("age estimate by AI is %s", age)
    
    if age >= 14 :
        credential = json.loads(open("./verifiable_credentials/Over13.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['KycId'] =  sha256(encoded_string)
        credential['credentialSubject']['KycProvider'] = 'Yoti'
        didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
        }
        credential_signed =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
        return jsonify(credential_signed)
    else :
        logging.warning("Age is estimated under 13")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_over18", "error_description" : "User is estimated under 13"}
        return Response(response=json.dumps(endpoint_response), status=403, headers=headers)  

# credential endpoint
async def ai_over18(mode) :
    try : 
        x_api_key = request.headers['X-API-KEY']
        wallet_request = request.get_json()    
    except :
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "request is not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    try :  
        wallet_did = wallet_request['did']
        did_authn = wallet_request["vp"]
        encoded_string = wallet_request["base64_encoded_string"].encode()
    except :
        logging.warning("Invalid data sent")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "data sent are not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    if  x_api_key != mode.altme_ai_token :
        logging.warning('api key does not match')
        endpoint_response= {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if  sha256(encoded_string) != json.loads(did_authn)['proof']['challenge'] :
        logging.warning("Challenge does not match")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "Challeng does not match"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    result = json.loads(await didkit.verify_presentation(did_authn, '{}'))['errors']
    if result :
        logging.warning("Verify presentation  error %s", result)
        #headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        #endpoint_response = {"error" : "invalid_proof", "error_description" : "The proof check fails"}
        # return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
   
    result = generate_session(encoded_string, mode)
    try :
        age = int(result['age'])
    except :
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : json.dumps(result)}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
      
    logging.info("age estimate by AI = %s", age)
    
    if age >= 19 :
        credential = json.loads(open("./verifiable_credentials/Over18.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['KycId'] =  sha256(encoded_string)
        credential['credentialSubject']['KycProvider'] = 'Yoti'
        didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
        }
        credential_signed =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
        return jsonify(credential_signed)
    else :
        logging.warning("Age is estimated under 18")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_over18", "error_description" : "User is estimated under 18"}
        return Response(response=json.dumps(endpoint_response), status=403, headers=headers)  