from flask import jsonify, request,  Response, render_template
import requests
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import didkit
from altme_on_chain import issue_sbt, register_tezid
from components import message

OFFER_DELAY = timedelta(seconds= 180)

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"


#curl -d '{"webhook" : "https://altme.io/webhook", "contact_email" :"thierry@gmail.io"}'  -H "Content-Type: application/json" -X POST https://talao.co/sandbox/op/beacon/verifier/api/create/over13
# curl -H "X-API-KEY: 123456" -X GET http://192.168.0.66:50000/tezotopia/membershipcard/123

def init_app(app,red, mode) :
    #app.add_url_rule('/tezotopia/qrcode',  view_func=tezotopia_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/tezotopia/membershipcard/<id>',  view_func=tezotopia_endpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    return


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
        
        # issue SBT
        # https://tzip.tezosagora.org/proposal/tzip-21/#creators-array
        """
        metadata = {
            "name":"Tezotopia Membership",
            "symbol":"ALTMESBT",
            "creators":["Altme.io","did:web:altme.io:did:web:app.altme.io:issuer"],
            "decimals":"0",
            "identifier" :  credential['id'],
            "displayUri":"ipfs://QmVCUKEdc3JcBs441o3dPEVz8A84dDypz9yotx68YkK7KW",
            "publishers":["compell.io"],
            "minter": "KT1JwgHTpo4NZz6jKK89rx3uEo9L5kLY1FQe",
            "rights": "No License / All Rights Reserved",
            "artifactUri": "ipfs://QmVCUKEdc3JcBs441o3dPEVz8A84dDypz9yotx68YkK7KW",
            "description":"During the next 365 days, when you will MINT an NFT on Tezotopia Starbase or buy a DROPS on Tezotopia Marketplace you will immediately receive a cashback on the Tezos blockchain address associated to this card. Please, use the same Tezos address to play on Tezotopia as the one you associated to this card. ID: Tezotopia Membership Card",
            "thumbnailUri": "ipfs://QmZgKuTdhmywKzaisjHQyskRodnxTESUiUdbVcrEeXYr14",
            "is_transferable":False,
            "shouldPreferSymbol":False
        }
        if issue_sbt(tezos_address, metadata, credential['id'], mode) :
            logging.info("SBT sent")
        """
        # register in whitelist on ghostnet KT1K2i7gcbM9YY4ih8urHBDbmYHLUXTWvDYj
        for address in  credential['credentialSubject']['associatedAddress']['blockchainTezos'] :
            tezotopia_membershipcard = "urn:uuid:0e7828d9-0591-4416-95c0-9b36b4d0e478"
            if register_tezid(address, tezotopia_membershipcard, "ghostnet", mode) :
                logging.info("Tezotopia address whitelisted %s", address)
                message.message("Tezotopia address whitelisted", "thierry@altme.io", address, mode)
            else :
                logging.info("Tezotopia address NOT whitelisted %s", address)
        # call tezotopia endpoint
        """
        curl -XPOST https://tezotopia.com/altme -H 'tezotopia-issuer-key:0e7828d9-0591-4416-95c0-9b36b4d0e478' 
        -H 'Content-Type: application/json' 
        --data '{ 
            "address": ["tz1UZZnrre9H7KzAufFVm7ubuJh5cCfjGwam", "tz2UZZnrre9H7KzAufFVm7ubuJh5cCfjkhgt],
            "device": "iphone 10",
            "systemVersion" : "16.1.1" 
            "over13": true }'
        """

        # send credential to wallet     
        message.message("Tezotopia membership card issued ", "thierry@altme.io", credential['credentialSubject']['id'], mode)
        return jsonify(signed_credential)

