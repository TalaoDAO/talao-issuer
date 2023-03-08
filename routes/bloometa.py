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

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"


#curl -d '{"webhook" : "https://altme.io/webhook", "contact_email" :"thierry@gmail.io"}'  -H "Content-Type: application/json" -X POST https://talao.co/sandbox/op/beacon/verifier/api/create/over13
# curl -H "X-API-KEY: 123456" -X GET http://192.168.0.66:50000/bloometa/membershipcard/123

def init_app(app,red, mode) :
    app.add_url_rule('/bloometa/qrcode',  view_func=bloometa_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/bloometa/membershipcard/<id>',  view_func=bloometa_endpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    return


def send_data_to_tezotopia(data, mode) :
    """

    curl -X POST \
        'https://bloometa.com/altme' \
        --header 'bloometa-issuer-key: 234465687-0591-4416-95c0-9b36b4d0e478' \
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
        'tezotopia-issuer-key' : mode.bloometa_issuer_key     
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
def bloometa_qrcode (mode) :
    return render_template(
        'qrcode_for_test.html',
        url=mode.server + 'bloometa/membershipcard/' + str(uuid.uuid1())
    )


async def bloometa_endpoint(id, red, mode): 
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
        credential = json.load(open('./verifiable_credentials/BloometaPass.jsonld', 'r'))
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential["issuer"] = issuer_did 
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
        credential_manifest = json.load(open('./credential_manifest/bloometapass_credential_manifest.json', 'r'))
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
        presentation_list =  json.loads(request.form['presentation'])
        for presentation in presentation_list :
            if isinstance(presentation, str) :
                presentation = json.loads(presentation)
            # tezos
            if presentation['verifiableCredential']['credentialSubject']['type'] == 'TezosAssociatedAddress' :
                address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
                if not credential['credentialSubject'].get('tezosAddress') :
                    credential['credentialSubject']['tezosAddress'] = [address]
                else :
                    credential['credentialSubject']['tezosAddress'].append(address)
            # Ethereum
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'EthereumAssociatedAddress' :
                address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
                if not credential['credentialSubject'].get('ethereumAddress') :
                    credential['credentialSubject']['ethereumAddress'] = [address]
                else :
                    credential['credentialSubject']['ethereumAddress'].append(address)
            # Polygon
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'PolygonAssociatedAddress' :
                address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
                if not credential['credentialSubject'].get('polygonAddress') :
                    credential['credentialSubject']['polygonAddress'] = [address]
                else :
                    credential['credentialSubject']['polygonAddress'].append(address)
            # Binance
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'BinanceAssociatedAddress' :
                address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
                if not credential['credentialSubject'].get('binanceAddress') :
                    credential['credentialSubject']['binanceAddress'] = [address]
                else :
                    credential['credentialSubject']['binanceAddress'].append(address)
            # Fantom
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'FantomAssociatedAddress' :
                address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
                if not credential['credentialSubject'].get('fantomAddress') :
                    credential['credentialSubject']['fantomAddress'] = [address]
                else :
                    credential['credentialSubject']['fantomAddress'].append(address)
            
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'WalletCredential' :
                deviceName = presentation['verifiableCredential']['credentialSubject']['deviceName']
                systemName = presentation['verifiableCredential']['credentialSubject']['systemName']

            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'Over18' :
                credential['credentialSubject']['ageOver'] = "18+"
            
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'EmailPass' :
                email = presentation['verifiableCredential']['credentialSubject']['email']
                
            else :
                logging.warning('non expected type %s',presentation['verifiableCredential']['credentialSubject']['type'] )

        if credential['credentialSubject'].get('ageOver') != "18+" :
            logging.warning('Over 18 not available')
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
       
        # call bloometa endpoint
        data = {
            'tezosAddress' :  credential['credentialSubject']['tezosAddress'],
            'ethereumAddress' :  credential['credentialSubject']['ethereumAddress'],
            'polygonAddress' :  credential['credentialSubject']['polygonAddress'],
            'binanceAddress' :  credential['credentialSubject']['binanceAddress'],
            'fantomAddress' :  credential['credentialSubject']['fantomAddress'],
            'email' : email,
            'device' : deviceName,
            'systemVersion' : systemName,
            'over18' : True
        }
        logging.info('data  = %s', data)
        send_data_to_tezotopia(data, mode)

        # send credential to wallet     
        message.message("Bloometa membership card issued ", "thierry@altme.io", credential['credentialSubject']['id'], mode)
        return jsonify(signed_credential)

