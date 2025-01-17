
from yoti_python_sdk.http import SignedRequest
from flask import jsonify, Response, request
import json
import requests
import logging
import uuid
from datetime import datetime, timedelta
import didkit
import hashlib
from components import message
import oidc

logging.basicConfig(level=logging.INFO)

EXPIRATION_DELAY = timedelta(weeks=52)
AGE_STORAGE = 300

key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"

PATHS = {
    "AGE": '/age',
    "LIVENESS": '/antispoofing',
    "AGE_LIVENESS": '/age-antispoofing'
}


def update_counter(vc_for_counter, mode):
    data = {
            "vc": vc_for_counter,
            "count": "1"
        }
    requests.post(mode.server + 'counter/update', data=data)


def init_app(app, red, mode):
    app.add_url_rule('/.well-known/openid-configuration', view_func=openid_configuration, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/.well-known/openid-credential-issuer', view_func=openid_configuration, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/ai/over13',  view_func=ai_over, methods=['POST'], defaults={'mode': mode, 'red': red, 'age_over': 13})
    app.add_url_rule('/ai/over18',  view_func=ai_over, methods=['POST'], defaults={'mode': mode, 'red': red, 'age_over': 18})
    app.add_url_rule('/ai/over15',  view_func=ai_over, methods=['POST'], defaults={'mode': mode, 'red': red, 'age_over': 15})
    app.add_url_rule('/ai/over21',  view_func=ai_over, methods=['POST'], defaults={'mode': mode, 'red': red, 'age_over': 21})
    app.add_url_rule('/ai/over50',  view_func=ai_over, methods=['POST'], defaults={'mode': mode, 'red': red, 'age_over': 50})
    app.add_url_rule('/ai/over65',  view_func=ai_over, methods=['POST'], defaults={'mode': mode, 'red': red, 'age_over': 65})
    app.add_url_rule('/ai/agerange',  view_func=ai_agerange, methods=['POST'], defaults={'mode': mode, 'red': red})
    app.add_url_rule('/ai/ageestimate',  view_func=ai_ageestimate, methods=['POST'], defaults ={'mode': mode, 'red': red})
    return


def openid_configuration(mode):
    credential_manifest = {
        "id": "Identity_cards",
        "issuer": {
            "id": "uuid:0001",
            "name": "Altme issuer"
        },
        "output_descriptors": []
    }
    for cm in ['over18', 'over13', 'over15', 'over21', 'over50', 'over65', 'agerange']:
        over = json.loads(open("./credential_manifest/" + cm + "_credential_manifest.json", 'r').read())['output_descriptors'][0]
        credential_manifest["output_descriptors"].append(over)
    oidc = {
        "issuer": mode.server,
        "token_endpoint": mode.server + 'token',
        "credential_endpoint": mode.server + 'credential',
        "credential_manifest": credential_manifest,
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic"
        ]
    }
    return jsonify(oidc)


def execute(request):
    response = requests.request(
        url=request.url, img=request.img, headers=request.headers, method=request.method)
    return response.content


def get_age_from_yoti(encoded_string, wallet_did, red, mode):
    try:
        data = json.loads(red.get(wallet_did).decode())
        age = data['age']
        st_dev = data['st_dev']
        prediction = data['prediction']
        logging.info("age is available in redis")
    except Exception:
        logging.info("call Yoti server")
        result = generate_session(encoded_string, mode)
        try:
            message.message_html("New request to Yoti", "thierry@altme.io", "", mode)
        except Exception:
            logging.warning("failed to send message")
        try:
            age = result['age']['age']
            st_dev = result['age']['st_dev']
            prediction = result['antispoofing']['prediction']
            data = {
                'age': age,
                'st_dev': st_dev,
                'prediction': prediction
            }
            red.setex(wallet_did, AGE_STORAGE, json.dumps(data))
            logging.info("age is now stored in redis")
        except Exception:
            logging.error(json.dumps(result))
            return None, None, None
    return age, st_dev, prediction
    

def generate_session(encoded_string, mode):
    img = {
        "img": encoded_string.decode("utf-8"),
        "img_validation_level": "low"
    }
    payload_string = json.dumps(img).encode()

    signed_request = (
        SignedRequest
        .builder()
        .with_pem_file(mode.yoti_pem_file)
        .with_base_url("https://api.yoti.com/ai/v1")
        .with_endpoint(PATHS['AGE_LIVENESS'])
        .with_http_method("POST")
        .with_header("X-Yoti-Auth-Id", mode.yoti)
        .with_payload(payload_string)
        .build()
    )
	# get Yoti response
    response = signed_request.execute()
    response_payload = json.loads(response.text)
    return response_payload


def sha256(x):
    return hashlib.sha256(x).digest().hex()


# credential endpoint
async def ai_ageestimate(red, mode):
    try: 
        x_api_key = request.headers['X-API-KEY']
        wallet_request = request.get_json()    
    except Exception:
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "request is not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    try:  
        wallet_did = wallet_request['did']
        encoded_string = wallet_request["base64_encoded_string"].encode()
    except Exception:
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "data sent are not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if x_api_key != mode.altme_ai_token:
        logging.warning('api key is incorrect')
        endpoint_response = {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    # test if age estimate has already been done recently by smae wallet
    age, st_dev, prediction = get_age_from_yoti(encoded_string, wallet_did, red, mode)
    if not age:
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": json.dumps(result)}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    logging.info("age estimate by AI is %s", age)
    logging.info("estimate quality by AI is %s", st_dev)
    logging.info("prediction is %s", prediction)
    
    if st_dev > 6:
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "Uncertain estimate"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    credential = json.loads(open("./verifiable_credentials/AgeEstimate.jsonld", 'r').read())
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
    credential['issuer'] = issuer_did
    credential['id'] = "urn:uuid:" + str(uuid.uuid1())
    credential['credentialSubject']['id'] = wallet_did
    credential['credentialSubject']['ageEstimate'] = str(age)
    credential['credentialSubject']['kycId'] = 'AI age estimate'
    credential['credentialSubject']['kycProvider'] = 'Yoti'
    didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
    }
    credential_signed = await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
    logging.info("VC age estimate is sent to wallet")
    return jsonify(credential_signed)


# credential endpoint General
async def ai_over(red, mode, age_over):    
    print("request args = ", request.args)
    if request.args.get('vc_format') in ["vcsd-jwt", "vc_sd_jwt"]:
        vc_format = "vcsd-jwt"
    else:
        vc_format = "ldp_vc"
    try:
        x_api_key = request.headers['X-API-KEY']
        wallet_request = request.get_json()
    except Exception:
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "request is not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    try:  
        wallet_did = wallet_request['did']
        encoded_string = wallet_request["base64_encoded_string"].encode()
    except Exception:
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "data sent are not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if x_api_key != mode.altme_ai_token:
        logging.warning('api key is incorrect')
        endpoint_response = {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    # test if age estimate has already been done recently
    age, st_dev, prediction = get_age_from_yoti(encoded_string, wallet_did, red, mode)
    if not age:
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "age not available"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if st_dev > 6:
        logging.warning("dev > 6")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "Uncertain estimate"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    credential_filename = '/Over' + str(age_over) + '.jsonld'
    vc_for_counter = 'over' + str(age_over)
    if vc_format == "ldp_vc":
        if age_over <= 21:
            age_over = age_over + 2  
        if age >= age_over:
            credential = json.loads(open("./verifiable_credentials/" + credential_filename, 'r').read())
            credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
            credential['issuer']["id"] = issuer_did
            credential['id'] = "urn:uuid:" + str(uuid.uuid1())
            credential['credentialSubject']['id'] = wallet_did
            didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
            }
            credential_signed = await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
        else:
            logging.warning("Age is estimated under %s", str(age_over))
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error": "invalid_over" + str(age_over), "error_description": "User is estimated under " + str(age_over)}
            return Response(response=json.dumps(endpoint_response), status=403, headers=headers)  
    elif vc_format == "vcsd-jwt":
        vc = {"vct": "urn:example:talao:age_over"}
        for age_in_vc in [12, 14, 16, 18, 21, 50, 65]:
            if age_in_vc <= 21:
                age_over = age_in_vc + 2
            else:
                age_over = age_in_vc
            if age >= age_over:
                vc.update({"age_over_" + str(age_in_vc): True})
            else:
                vc.update({"age_over_" + str(age_in_vc): False})
        credential_signed = oidc.sign_sd_jwt(vc, key, issuer_did, wallet_did, duration=365*24*60*60, kid=issuer_vm)
        logging.info("credential vc+sd-jwt = %s", credential_signed)
    else:
        logging.warning("VC format not supported")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "VC format not supported"}
        return Response(response=json.dumps(endpoint_response), status=403, headers=headers)  
    # update counter
    update_counter(vc_for_counter, mode)
    logging.info("VC %s is sent to wallet", vc_for_counter)
    return jsonify(credential_signed)
    

    # agerange credential endpoint
async def ai_agerange(red, mode):
    try:
        x_api_key = request.headers['X-API-KEY']
        wallet_request = request.get_json()    
    except Exception:
        logging.warning("Invalid request")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "request is not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    try:
        wallet_did = wallet_request['did']
        encoded_string = wallet_request["base64_encoded_string"].encode()
    except Exception:
        logging.warning("Invalid data sent")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "data sent are not correctly formated"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    if x_api_key != mode.altme_ai_token:
        logging.warning('api key does not match')
        endpoint_response = {"error": "unauthorized_client"}
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    age, st_dev, prediction = get_age_from_yoti(encoded_string, wallet_did, red, mode)
    if not age:
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": json.dumps(result)}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if st_dev > 6:
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error": "invalid_request", "error_description": "Uncertain estimate"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    credential = json.loads(open("./verifiable_credentials/AgeRange.jsonld", 'r').read())
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
    credential['issuer'] = issuer_did
    credential['id'] = "urn:uuid:" + str(uuid.uuid1())
    credential['credentialSubject']['id'] = wallet_did
    credential['credentialSubject']['kycId'] =  'AI age estimate'
    credential['credentialSubject']['kycProvider'] = 'Yoti'
    credential['credentialSubject']['kycMethod'] = 'Yoti artificial intelligence engine'

    #age range: "-13" or "14-17” or “18-24”, “25-34”, “35-44”, “45-54”, “55-64”, “65+”.
    if age < 15:
        credential['credentialSubject']['ageRange'] = "-13"
    if age < 18:
        credential['credentialSubject']['ageRange'] = "14-17"
    elif age < 25:
        credential['credentialSubject']['ageRange'] = "18-24"
    elif age < 35:
        credential['credentialSubject']['ageRange'] = "25-34"
    elif age < 45:
        credential['credentialSubject']['ageRange'] = "35-44"
    elif age < 55:
        credential['credentialSubject']['ageRange'] = "45-54"
    elif age < 65:
        credential['credentialSubject']['ageRange'] = "55-64"
    else:
        credential['credentialSubject']['ageRange'] = "65+"
    
    expiration = datetime.now() + timedelta(weeks=52)
    credential['expirationDate'] = expiration.replace(microsecond=0).isoformat() + "Z"

    didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
        }
    signed_credential = await didkit.issue_credential(
            json.dumps(credential),
            didkit_options.__str__().replace("'", '"'),
            key
    )
    # update counter
    update_counter("agerange", mode)
    
    logging.info("VC AgeRange is sent to wallet")
    return jsonify(signed_credential)