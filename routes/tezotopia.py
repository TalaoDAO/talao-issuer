from flask import jsonify, request,  Response
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import didkit

OFFER_DELAY = timedelta(seconds= 10*60)
CODE_DELAY = timedelta(seconds= 180)
QRCODE_DELAY = 60

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"


#curl -d '{"webhook" : "https://altme.io/webhook", "contact_email" :"thierry@gmail.io"}'  -H "Content-Type: application/json" -X POST https://talao.co/sandbox/op/beacon/verifier/api/create/over13
# curl -H "X-API-KEY: 123456" -X GET http://192.168.0.66:50000/tezotopia/membershipcard/123

def init_app(app,red, mode) :
    app.add_url_rule('/tezotopia/membershipcard/<id>',  view_func=tezotopia_enpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    return

async def tezotopia_enpoint(id, red, mode): 
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
        return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

    if request.method == 'GET': 
        credential = json.load(open('./verifiable_credentials/MembershipCard_1.jsonld', 'r'))
        credential["issuer"] = issuer_did 
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
        credential_manifest = json.load(open('./credential_manifest/tezotopia_membershipcard_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        red.setex(id, 180, json.dumps(credential))
        credential['credentialSubject']['id'] = "did:wallet"
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat(),
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)

    else :  #POST
        # init credential
        credential = json.loads(red.get(id).decode())
        credential['credentialSubject']['id'] = request.form['subject_id']
        credential['credentialSubject']['offers']['benefit']['discount'] = '25%'
        presentation_list =  request.form['presentation']
        over13 = False
        for presentation in presentation_list :
            if json.loads(presentation)['credentialSubject']['type'] == 'tezosAssociatedAddress' :
                credential['credentialSubject']['associatedAddress']['blockchainTezos'] = json.loads(presentation)['credentialSubject']['associatedAddress']
            if json.loads(presentation)['credentialSubject']['type'] == 'Over13' :
                over13 = True
        if not over13 :
            logging.warning('Over 13 not available')
            endpoint_response= {"error": "unauthorized_client"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

        # signature 
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
            }
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        if not signed_credential :         # send event to client agent to go forward
            logging.error('credential signature failed')
            return jsonify('Server failed'), 500
        # Success : send event to client agent to go forward
        return jsonify(signed_credential)
 
