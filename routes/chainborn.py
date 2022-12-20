from flask import jsonify, request,  Response, render_template
import requests
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
import didkit
from components import message

OFFER_DELAY = timedelta(seconds= 180)
WEBHOOK_URL = "https://altme.io"
WEBHOOK_KEY = "4507a516-7fc5-11ed-a744-fb322650eae0"


issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"


def init_app(app,red, mode) :
    app.add_url_rule('/chainborn/qrcode',  view_func=chainborn_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/chainborn/membershipcard/<id>',  view_func=chainborn_endpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    return


# pour tester l issuer avec un qrcode
def chainborn_qrcode (mode) :
    return render_template(
        'qrcode_for_test.html',
        url=mode.server + 'chainborn/membershipcard/' + str(uuid.uuid1())
    )


async def chainborn_endpoint(id, red, mode): 
    # a mettre en prod
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
        credential = json.load(open('./verifiable_credentials/Chainborn_MembershipCard.jsonld', 'r'))
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential["issuer"] = issuer_did 
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
        credential_manifest = json.load(open('./credential_manifest/chainborn_membershipcard_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
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
        presentation_list =  json.loads(request.form['presentation'])
        for presentation in presentation_list :
            if isinstance(presentation, str) :
                presentation = json.loads(presentation)
            # get all tezos addresses
            if presentation['verifiableCredential']['credentialSubject']['type'] == 'TezosAssociatedAddress' :
                tezos_address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
                if not credential['credentialSubject']['associatedAddress']['blockchainTezos'] :
                    credential['credentialSubject']['associatedAddress']['blockchainTezos'] = tezos_address
                else :
                    if isinstance(credential['credentialSubject']['associatedAddress']['blockchainTezos'], str) :
                        credential['credentialSubject']['associatedAddress']['blockchainTezos'] = credential['credentialSubject']['associatedAddress']['blockchainTezos'].split()
                    credential['credentialSubject']['associatedAddress']['blockchainTezos'].append(tezos_address)
            # get email
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'EmailPass' :
                credential['credentialSubject']['email'] = presentation['verifiableCredential']['credentialSubject']['email']
            else :
                logging.warning('non expected type %s',presentation['verifiableCredential']['credentialSubject']['type'] )
        
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
            }
        try : 
            signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        except :
            logging.error('credential signature failed')
            endpoint_response= {"error": "server_error"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=500, headers=headers)
        
        # send data to application webhook
        headers = {
            "'X-API-KEY'" : WEBHOOK_KEY,
            "Content-Type": "application/json" 
        }       
        payload = { 'event' : 'ISSUANCE',
             #'vp': json.loads(request.form['presentation']),
            "id": id,
            "address" :  credential['credentialSubject']['associatedAddress']['blockchainTezos'],
            "email" :  credential['credentialSubject']['email']
        }
        logging.info("event ISSUANCE sent to webhook %s", payload)
        r = requests.post(WEBHOOK_URL,  data=json.dumps(payload), headers=headers)
        if not 199<r.status_code<300 :
            logging.error('issuer failed to send to  application webhook, status code = %s', r.status_code)
      
        # send credential to wallet        
        return jsonify(signed_credential)

