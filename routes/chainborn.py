from flask import jsonify, request,  Response, render_template
import requests
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
import didkit
from components import message
from altme_on_chain import register_tezid


OFFER_DELAY = timedelta(seconds= 180)


issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"


def hasSummoned(address_list):
    for address in address_list:
        url = "https://api.mainnet.tzkt.io/v1/accounts/KT1Nr4CLi7hY7QrZe8D4ar6uihpnr7nRtGJH/operations?initiator=" + address + "&entrypoint=add_hero&status=applied"
        r = requests.get(url)
        if not 199 < r.status_code < 300 :
            logging.error('issuer failed to call TzKT, status code = %s', r.status_code)
            return False
        logging.info("data from Chainborn = %s", r.json())
        if r.json() :
            logging.info("address = %s", address)
            return True
    return False


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
                    credential['credentialSubject']['associatedAddress']['blockchainTezos'] = [tezos_address]
                else :
                    credential['credentialSubject']['associatedAddress']['blockchainTezos'].append(tezos_address)
            # get email
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'EmailPass' :
                credential['credentialSubject']['email'] = presentation['verifiableCredential']['credentialSubject']['email']
            else :
                logging.warning('non expected type %s',presentation['verifiableCredential']['credentialSubject']['type'] )
          
        if not hasSummoned(credential['credentialSubject']['associatedAddress']['blockchainTezos']) :
            return jsonify('User has not summoned a Hero !'), 412

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
        
        # update counter
        data = {"vc" : "chainborn" , "count" : "1" }
        requests.post(mode.server + 'counter/update', data=data)

        # send data to application webhook
        headers = {
            "chainborn-api-key" : mode.chainborn_api_key,
            "Content-Type": "application/json" 
        }    
        payload = { 
            "id": id,
            "address" :  credential['credentialSubject']['associatedAddress']['blockchainTezos'],
            "email" :  credential['credentialSubject']['email']
        }
        logging.info("event ISSUANCE sent to webhook %s", payload)
        r = requests.post("https://chainborn.xyz/membership",  data=json.dumps(payload), headers=headers)
        logging.info("Chainborn server return = %s",r.text)
      
        # register in whitelist 
        chainborn_membershipcard = "urn:uuid:0e57d9-0591-4444-95c0-9b363453578"
        for address in credential['credentialSubject']['associatedAddress']['blockchainTezos'] :
            if register_tezid(address, chainborn_membershipcard, "mainnet", mode) :
                logging.info("address whitelisted %s", address)
                message.message("Chainborn address whitelisted", "thierry@altme.io", address, mode)
        
        # send credential to wallet
        message.message("Chainborn membership card issued ", "thierry@altme.io", credential['credentialSubject']['id'], mode)
        return jsonify(signed_credential)

