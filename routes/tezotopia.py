from flask import jsonify, request,  Response, render_template
import requests
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import didkit
from altme_on_chain import register_tezid
from components import message

OFFER_DELAY = timedelta(seconds= 180)

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"


#curl -d '{"webhook" : "https://altme.io/webhook", "contact_email" :"thierry@gmail.io"}'  -H "Content-Type: application/json" -X POST https://talao.co/sandbox/op/beacon/verifier/api/create/over13
# curl -H "X-API-KEY: 123456" -X GET http://192.168.0.66:50000/tezotopia/membershipcard/123

def init_app(app,red, mode) :
    app.add_url_rule('/tezotopia/qrcode',  view_func=tezotopia_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/tezotopia/membershipcard/<id>',  view_func=tezotopia_endpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    return


def send_data_to_tezotopia(data, mode) :
    """

    curl -X POST \
        'https://us-central1-tezotopia-testnet.cloudfunctions.net/altme' \
        --header 'tezotopia-issuer-key: 0e7828d9-0591-4416-95c0-9b36b4d0e478' \
        --header 'Content-Type: application/json' \
        --data-raw '{
        "address": ["tz1test", "tz2test"],
        "device": "Test",
        "systemVersion": "1.0",
        "over13": true,
        "anythingElse": "value"
        }'
    
    """
    url = 'https://us-central1-tezotopia-testnet.cloudfunctions.net/altme'
    headers = {
        'Content-Type' : 'application/json',
        'tezotopia-issuer-key' : mode.tezotopia_issuer_key     
    }
    r = requests.post(url, headers=headers, data=json.dumps(data))
    logging.info("Send data : status code = %s", r.status_code)
    if not 199<r.status_code<300 :
        logging.error("API call to Tezootpia rejected %s", r.status_code)
        return
    else :
        logging.info('Data has been sent to Tezotopia')
        return True


# pour tester l issuer avec un qrcode
def tezotopia_qrcode (mode) :
    return render_template(
        'qrcode_for_test.html',
        url=mode.server + 'tezotopia/membershipcard/' + str(uuid.uuid1())
    )


async def tezotopia_endpoint(id, red, mode): 
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
        credential = json.load(open('./verifiable_credentials/MembershipCard_1.jsonld', 'r'))
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential["issuer"] = issuer_did 
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        duration = int(credential['credentialSubject']['offers'].get('duration', 365))
        credential['expirationDate'] =  (datetime.now() + timedelta(days= duration)).isoformat() + "Z"
        credential_manifest = json.load(open('./credential_manifest/tezotopia_membershipcard_credential_manifest.json', 'r'))
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
        # init credential
        try :
            credential = json.loads(red.get(id).decode())
        except :
            logging.error("redis get id failed")
            endpoint_response= {"error": "delay_expired"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)

        credential['credentialSubject']['id'] = request.form['subject_id']
        credential['credentialSubject']['offers']['analytics'] = "https://talao.co/analytics/did/" + credential['credentialSubject']['id']
        presentation_list =  json.loads(request.form['presentation'])
        for presentation in presentation_list :
            if isinstance(presentation, str) :
                presentation = json.loads(presentation)
            
            if presentation['verifiableCredential']['credentialSubject']['type'] == 'TezosAssociatedAddress' :
                tezos_address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
                if not credential['credentialSubject']['associatedAddress']['blockchainTezos'] :
                    credential['credentialSubject']['associatedAddress']['blockchainTezos'] = [tezos_address]
                else :
                    credential['credentialSubject']['associatedAddress']['blockchainTezos'].append(tezos_address)
            
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'Over13' :
                credential['credentialSubject']['ageOver'] = "13+"
            
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'EmailPass' :
                email = presentation['verifiableCredential']['credentialSubject']['email']
            
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'WalletCredential' :
                deviceName = presentation['verifiableCredential']['credentialSubject']['deviceName']
                systemName = presentation['verifiableCredential']['credentialSubject']['systemName']

            else :
                logging.warning('non expected type %s',presentation['verifiableCredential']['credentialSubject']['type'] )

        if credential['credentialSubject'].get('ageOver') not in ["13+", "18+"] :
            logging.warning('Over 13/18 not available')
            endpoint_response= {"error": "unauthorized_client"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
                
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
        
        # update analytics   
        url = 'https://talao.co/analytics/api/newvoucher'   
        headers = { "key" : mode.analytics_key2,
                    "Content-Type": "application/x-www-form-urlencoded"
        }
        resp = requests.post(url, data=signed_credential, headers=headers)
        if not 199<resp.status_code<300 :
            logging.warning("Get access refused, analytics are not updated ", resp.status_code)
        
        # register in whitelist on ghostnet KT1K2i7gcbM9YY4ih8urHBDbmYHLUXTWvDYj
        for address in  credential['credentialSubject']['associatedAddress']['blockchainTezos'] :
            tezotopia_membershipcard = "urn:uuid:0e7828d9-0591-4416-95c0-9b36b4d0e478"
            if register_tezid(address, tezotopia_membershipcard, "ghostnet", mode) :
                logging.info("Tezotopia address whitelisted %s", address)
                message.message("Tezotopia address whitelisted", "thierry@altme.io", address, mode)
            else :
                logging.info("Tezotopia address Not whitelisted %s", address)
        
        # call tezotopia endpoint
        data = {
            'address' : credential['credentialSubject']['associatedAddress']['blockchainTezos'],
            'email' : email,
            'device' : deviceName,
            'systemVersion' : systemName,
            'over13' : True
        }
        logging.info('data  = %s', data)
        send_data_to_tezotopia(data, mode)

        # send credential to wallet     
        message.message("Tezotopia membership card issued ", "thierry@altme.io", credential['credentialSubject']['id'], mode)
        return jsonify(signed_credential)

