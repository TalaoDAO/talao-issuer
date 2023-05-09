
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


logging.basicConfig(level=logging.INFO)

EXPIRATION_DELAY = timedelta(weeks=52)

key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"

PATHS = {
    "AGE": '/age',
    "LIVENESS": '/antispoofing',
    "AGE_LIVENESS": '/age-antispoofing'
}

def init_app(app,red, mode) :
    app.add_url_rule('/ai/over13',  view_func=ai_over13, methods = ['POST'], defaults ={'mode' : mode, 'red' : red})
    app.add_url_rule('/ai/over18',  view_func=ai_over18, methods = ['POST'], defaults ={'mode' : mode, 'red' : red})
    app.add_url_rule('/ai/over15',  view_func=ai_over15, methods = ['POST'], defaults ={'mode' : mode, 'red' : red})
    app.add_url_rule('/ai/agerange',  view_func=ai_agerange, methods = ['POST'], defaults ={'mode' : mode, 'red' : red})
    app.add_url_rule('/ai/ageestimate',  view_func=ai_ageestimate, methods = ['POST'], defaults ={'mode' : mode, 'red' : red})
    return


def execute(request):
    response = requests.request(
        url=request.url, img=request.img, headers=request.headers, method=request.method)
    return response.content


def generate_session(encoded_string, mode):
    img = {"img" : encoded_string.decode("utf-8"),
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


def sha256 (x) :
    return hashlib.sha256(x).digest().hex()


# credential endpoint
async def ai_ageestimate(red, mode) :
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
        challenge = json.loads(did_authn)['proof']['challenge']
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

    if  sha256(encoded_string) != challenge :
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
    
    # test if age estimate has already been done recently
    try :
        data = json.loads(red.get(challenge).decode())
        age = data['age']
        st_dev = data['st_dev']
        prediction = data['prediction']
        logging.info("age is available in redis")
    except :   
        logging.info("call Yoti server")
        result = generate_session(encoded_string, mode)
        try :
            message.message_html("New request to Yoti", "thierry@altme.io", "", mode)
        except :
            logging.warning("failed to send message")
        try :
            age = result['age']['age']
            st_dev = result['age']['st_dev']
            prediction = result['antispoofing']['prediction']
            data = {'age' : age,
                     'st_dev' : st_dev,
                     'prediction' : prediction}
            red.setex(challenge, 240, json.dumps(data))
            logging.info("age is now stored in redis for 240s")
        except :
            logging.error(json.dumps(result))
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_request", "error_description" : json.dumps(result)}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    logging.info("age estimate by AI is %s", age)
    logging.info("estimate quality by AI is %s", st_dev)
    logging.info("prediction is %s", prediction)
    
    #if prediction != 'real' :
    #    logging.warning('prediction = %s', prediction)
    
    if st_dev > 6  :
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "Uncertain estimate"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    credential = json.loads(open("./verifiable_credentials/AgeEstimate.jsonld", 'r').read())
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
    credential['issuer'] = issuer_did
    credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
    credential['credentialSubject']['id'] = wallet_did
    credential['credentialSubject']['ageEstimate'] = str(age)
    credential['credentialSubject']['kycId'] =  'AI age estimate'
    credential['credentialSubject']['kycProvider'] = 'Yoti'
    didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
    }
    credential_signed =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
    logging.info("VC age estimate is sent to wallet")
    return jsonify(credential_signed)


# credential endpoint
async def ai_over13(red, mode) :
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
        challenge = json.loads(did_authn)['proof']['challenge']
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

    if  sha256(encoded_string) != challenge :
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
    
    # test if age estimate has already been done recently
    try :
        data = json.loads(red.get(challenge).decode())
        age = data['age']
        st_dev = data['st_dev']
        prediction = data['prediction']
        logging.info("age is available in redis")
    except :   
        logging.info("call Yoti server, age not available")
        result = generate_session(encoded_string, mode)
        try :
            age = result['age']['age']
            st_dev = result['age']['st_dev']
            prediction = result['antispoofing']['prediction']
            data = {'age' : age,
                     'st_dev' : st_dev,
                     'prediction' : prediction}
            red.setex(challenge, 240, json.dumps(data))
            logging.info("age is stored in redis for 240 sec")
        except :
            logging.warning(json.dumps(result))
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_request", "error_description" : json.dumps(result)}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    #logging.info("age estimate by AI is %s", age)
    #logging.info("estimate quality by AI is %s", st_dev)
    
    if st_dev > 6  :
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "Uncertain estimate"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    if age >= 15 :
        credential = json.loads(open("./verifiable_credentials/Over13.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] =  'AI age estimate'
        credential['credentialSubject']['kycProvider'] = 'Yoti'
        credential['credentialSubject']['kycMethod'] = 'Yoti artificial intelligence engine'
        didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
        }
        credential_signed =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
        
        # update counter
        data = {"vc" : "over13" , "count" : "1" }
        requests.post(mode.server + 'counter/update', data=data)
        
        logging.info("VC Over13 is sent to wallet")
        return jsonify(credential_signed)
    else :
        logging.warning("Age is estimated under 13")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_over13", "error_description" : "User is estimated under 13"}
        return Response(response=json.dumps(endpoint_response), status=403, headers=headers)  



# credential endpoint
async def ai_over15(red, mode) :
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
        challenge = json.loads(did_authn)['proof']['challenge']
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

    if  sha256(encoded_string) != challenge :
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
    
    # test if age estimate has already been done recently
    try :
        data = json.loads(red.get(challenge).decode())
        age = data['age']
        st_dev = data['st_dev']
        prediction = data['prediction']
        logging.info("age is available in redis")
    except :   
        logging.info("call Yoti server, age not available")
        result = generate_session(encoded_string, mode)
        try :
            age = result['age']['age']
            st_dev = result['age']['st_dev']
            prediction = result['antispoofing']['prediction']
            data = {'age' : age,
                     'st_dev' : st_dev,
                     'prediction' : prediction}
            red.setex(challenge, 240, json.dumps(data))
            logging.info("age is stored in redis for 240 sec")
        except :
            logging.warning(json.dumps(result))
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_request", "error_description" : json.dumps(result)}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if st_dev > 6  :
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "Uncertain estimate"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    if age >= 17 :
        credential = json.loads(open("./verifiable_credentials/Over15.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] =  'AI age estimate'
        credential['credentialSubject']['kycProvider'] = 'Yoti'
        credential['credentialSubject']['kycMethod'] = 'Yoti artificial intelligence engine'
        didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
        }
        credential_signed =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
        
        # update counter
        data = {"vc" : "over15" , "count" : "1" }
        requests.post(mode.server + 'counter/update', data=data)

        logging.info("VC Over15 is sent to wallet")
        return jsonify(credential_signed)
    else :
        logging.warning("Age is estimated under 15")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_over13", "error_description" : "User is estimated under 13"}
        return Response(response=json.dumps(endpoint_response), status=403, headers=headers)  


# credential endpoint
async def ai_over18(red,mode) :
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
        challenge = json.loads(did_authn)['proof']['challenge']
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

    if  sha256(encoded_string) != challenge :
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
   
    #test if age estimate has already been done recently
    try :
        data = json.loads(red.get(challenge).decode())
        age = data['age']
        st_dev = data['st_dev']
        prediction = data['prediction']
        logging.info("age is available in redis")
    except :   
        logging.info("call Yoti server, age not available")
        result = generate_session(encoded_string, mode)
        try :
            age = result['age']['age']
            st_dev = result['age']['st_dev']
            prediction = result['antispoofing']['prediction']
            data = {'age' : age,
                    'st_dev' : st_dev,
                    'prediction' : prediction}
            red.setex(challenge, 240, json.dumps(data))
            logging.info("age is stored in redis for 240 sec")
        except :
            logging.warning(json.dumps(result))
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_request", "error_description" : json.dumps(result)}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    
    if st_dev > 6 :
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "Uncertain estimate"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if age >= 20.3 :
        credential = json.loads(open("./verifiable_credentials/Over18.jsonld", 'r').read())
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
        credential['issuer'] = issuer_did
        credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = wallet_did
        credential['credentialSubject']['kycId'] =  'AI age estimate'
        credential['credentialSubject']['kycProvider'] = 'Yoti'
        credential['credentialSubject']['kycMethod'] = 'Yoti artificial intelligence engine'
        didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": issuer_vm
        }
        credential_signed =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key)
        
        # update counter
        data = {"vc" : "over18" , "count" : "1" }
        requests.post(mode.server + 'counter/update', data=data)

        logging.info("VC Over18 is sent to wallet")
        return jsonify(credential_signed)
    else :
        logging.warning("Age is estimated under 18")
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_over18", "error_description" : "User is estimated under 18"}
        return Response(response=json.dumps(endpoint_response), status=403, headers=headers)  


    # credential endpoint
async def ai_agerange(red, mode) :
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
        challenge = json.loads(did_authn)['proof']['challenge']
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

    if  sha256(encoded_string) != challenge :
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
   
     #test if age estimate has already been done recently
    try :
        data = json.loads(red.get(challenge).decode())
        age = data['age']
        st_dev = data['st_dev']
        prediction = data['prediction']
        logging.info("age is available in redis")
    except :   
        logging.info("call Yoti server, age not available")
        result = generate_session(encoded_string, mode)
        try :
            age = result['age']['age']
            st_dev = result['age']['st_dev']
            prediction = result['antispoofing']['prediction']
            data = {'age' : age,
                     'st_dev' : st_dev,
                     'prediction' : prediction}
            red.setex(challenge, 240, json.dumps(data))
            logging.info("age is stored in redis for 240 sec")
        except :
            logging.warning(json.dumps(result))
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_request", "error_description" : json.dumps(result)}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
    #logging.info("age estimate by AI is %s", age)
    #logging.info("estimate quality by AI is %s", st_dev)
    
    if st_dev > 6  :
        logging.warning(json.dumps(result))
        headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        endpoint_response = {"error" : "invalid_request", "error_description" : "Uncertain estimate"}
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
  
    credential = json.loads(open("./verifiable_credentials/AgeRange.jsonld", 'r').read())
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (datetime.now() + EXPIRATION_DELAY).replace(microsecond=0).isoformat() + "Z"
    credential['issuer'] = issuer_did
    credential['id'] =  "urn:uuid:" + str(uuid.uuid1())
    credential['credentialSubject']['id'] = wallet_did
    credential['credentialSubject']['kycId'] =  'AI age estimate'
    credential['credentialSubject']['kycProvider'] = 'Yoti'
    credential['credentialSubject']['kycMethod'] = 'Yoti artificial intelligence engine'

    #age range : "-13" or "14-17” or “18-24”, “25-34”, “35-44”, “45-54”, “55-64”, “65+”.
    if age < 15 :
        credential['credentialSubject']['ageRange'] = "-13"
    if age < 18 :
        credential['credentialSubject']['ageRange'] = "14-17"
    elif age < 25 :
        credential['credentialSubject']['ageRange'] = "18-24"
    elif age < 35 :
        credential['credentialSubject']['ageRange'] = "25-34"
    elif age < 45 :
        credential['credentialSubject']['ageRange'] = "35-44"
    elif age < 55 :
        credential['credentialSubject']['ageRange'] = "45-54"
    elif age < 65 :
        credential['credentialSubject']['ageRange'] = "55-64"
    else :
        credential['credentialSubject']['ageRange'] = "65+"
    
    expiration = datetime.now() + timedelta(weeks=52)
    credential['expirationDate'] = expiration.replace(microsecond=0).isoformat() + "Z"

    didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
        }
    signed_credential =  await didkit.issue_credential(
            json.dumps(credential),
            didkit_options.__str__().replace("'", '"'),
            key
    )
    # update counter
    data = {"vc" : "agerange" , "count" : "1" }
    requests.post(mode.server + 'counter/update', data=data)
    
    logging.info("VC AgeRange is sent to wallet")
    return jsonify(signed_credential)