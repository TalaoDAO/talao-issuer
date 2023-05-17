from flask import jsonify, request,  Response, render_template
import requests
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import didkit
from components import message

OFFER_DELAY = timedelta(seconds= 180)
ISSUER_KEY = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
ISSUER_VM = "did:web:app.altme.io:issuer#key-1"
ISSUER_DID = "did:web:app.altme.io:issuer"
PEP_URL = 'https://pepchecker.com/api/v1/'


test_first_name = "paul"
test_last_name = "lanser"
test_birth_date = "1963-09-13"   #%Y-%m-%d
test_api_key = "test-4427356f-be6d-4cfa-bf22-e8172184e56d"

#curl -d '{"webhook" : "https://altme.io/webhook", "contact_email" :"thierry@gmail.io"}'  -H "Content-Type: application/json" -X POST https://talao.co/sandbox/op/beacon/verifier/api/create/over13
# curl -H "X-API-KEY: 123456" -X GET http://192.168.0.66:50000/tezotopia/membershipcard/123


def init_app(app,red, mode) :
    app.add_url_rule('/defi/qrcode',  view_func=defi_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/defi/card/<id>',  view_func=defi_endpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    return


def pep(firstname, lastname, mod, mode) :
    uri = PEP_URL + 'check?firstName=' + firstname + '&lastName=' + lastname
    if mod == 'test' :
        api_key = test_api_key
    else:
        api_key = mode.pep_api_key
    response = requests.get( uri, headers={'api-key':  api_key})
    logging.info('PEP = %s',response.json() )
    return not response.json()['sanctionList'] 


# pour tester l issuer avec un qrcode
def defi_qrcode (mode) :
    return render_template(
        'qrcode_for_test.html',
        url=mode.server + 'defi/card/' + str(uuid.uuid1()) + "?mode=" + request.args.get('mode', 'prod')
    )


async def defi_endpoint(id, red, mode): 
    if mode.myenv == 'aws' :
        try : 
            x_api_key = request.headers['X-API-KEY']
        except :
            logging.warning("Invalid request")
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            endpoint_response = {"error" : "invalid_request", "error_description" : "request is not correctly formated"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)    
        if  x_api_key != mode.altme_ai_token :
            logging.warning('api key is incorrect')
            endpoint_response= {"error": "unauthorized_client"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=401, headers=headers)
    
    if request.method == 'GET': 
        credential = json.load(open('./verifiable_credentials/DefiCompliance.jsonld', 'r'))
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential["issuer"] = ISSUER_DID 
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now() + timedelta(days= 30)).isoformat() + "Z"
        credential_manifest = json.load(open('./credential_manifest/defi_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        red.setex(id, 360, json.dumps(credential))
        credential['credentialSubject']['id'] = "did:wallet"
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat(),
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)

    else :  #POST
        print(request.args.get("mode"))
        if request.args.get("mode") == 'test' :
            mod = 'test'
        else :
            mod = "prod"
        logging.info("mode defi compliance = %s", mod)
        # init credential
        try :
            credential = json.loads(red.get(id).decode())
        except :
            logging.error("redis get id failed")
            endpoint_response= {"error": "delay_expired"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
        credential['credentialSubject']['id'] = request.form['subject_id']
        presentation_list = json.loads(request.form['presentation'])
        # if several VCs are presented one take the first VC presented
        if isinstance(presentation_list, list) :
            presentation = json.loads(presentation_list[0])
        else :
            presentation = presentation_list
        verifiable_id = presentation['verifiableCredential']
        birth_date = verifiable_id['credentialSubject']['dateOfBirth']
        first_name = verifiable_id['credentialSubject']['firstName']
        last_name  = verifiable_id['credentialSubject']['familyName']
        if mod == 'test' :
            first_name = test_first_name 
            last_name = test_last_name
            birth_date = test_birth_date
        # check age
        current_date = datetime.now()
        date1 = datetime.strptime(birth_date,'%Y-%m-%d') + timedelta(weeks=18*52)
        if (current_date > date1) :
            credential['credentialSubject']['ageCheck'] = "Succeeded"
        else :
            credential['credentialSubject']['ageCheck'] = "Failed"
        # check sanction list
        if pep(first_name, last_name, mod, mode) :
            pep_result = "Succeeded"
        else :
            pep_result = "Failed"
        credential['credentialSubject']['sanctionListCheck'] = pep_result        
        # AML compliance 
        if credential['credentialSubject']['sanctionListCheck'] == "Succeeded" and credential['credentialSubject']['ageCheck'] == "Succeeded" :
            credential['credentialSubject']['amlComplianceCheck'] = "Succeeded"
        else :
            credential['credentialSubject']['amlComplianceCheck'] = "Failed"
        """
        if credential['credentialSubject'].get('ageOver') not in ["13+", "18+"] :
            logging.warning('Over 13/18 not available')
            endpoint_response= {"error": "unauthorized_client"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
         """       
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": ISSUER_VM
            }
        try : 
            signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                ISSUER_KEY)
        except :
            logging.error('credential signature failed')
            endpoint_response= {"error": "server_error"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=500, headers=headers)

        # send credential to wallet     
        message.message("DeFi card issued ", "thierry@altme.io", credential['credentialSubject']['id'], mode)
        return jsonify(signed_credential)

