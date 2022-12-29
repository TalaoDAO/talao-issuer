from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from components import message
import requests
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
from urllib.parse import urlencode
import didkit

OFFER_DELAY = timedelta(seconds= 10*60)
CODE_DELAY = timedelta(seconds= 180)
QRCODE_DELAY = 60

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"

def init_app(app,red, mode) :
    app.add_url_rule('/twitter/<id>',  view_func=twitter_endpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    return

   
async def twitter_endpoint(id, red, mode):
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
        # make an offer  
        credential = json.load(open('./verifiable_credentials/TwitterAccountProof.jsonld', 'r'))
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential["issuer"] = issuer_did 
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
        credential_manifest = json.load(open('./credential_manifest/twitter_credential_manifest.json', 'r'))
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['id'] = "urn:uuid:random"
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
        presentation = json.loads(request.form['presentation'])
        address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
        url = "https://api.tzprofiles.com/" + address
        r = requests.get(url)
        if not 199<r.status_code<300 :
            logging.error("API call rejected %s", r.status_code)
            return jsonify('Server failed'), 500

    # treatment of API data
        tzprofiles_result = r.json()
        if not tzprofiles_result :
            logging.warning('TzProfiles not found')
            return jsonify('User does not have a Tezos Profiles'), 412
        for data in tzprofiles_result :
            for vc in data :
                try :
                    credential['credentialSubject']['sameAs'] = json.loads(vc)['credentialSubject']['sameAs']
                    credential['evidence'] = json.loads(vc)['evidence']
                except :
                    pass
        if not credential['credentialSubject'].get('sameAs') :
            logging.warning('Twitter acconut not found on Tezos Profiles')
            return jsonify('User does not have a Twitter account registered on Tezos Profiles'), 412
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
 