from flask import jsonify, request,  Response
import requests
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import didkit

OFFER_DELAY = timedelta(seconds= 180)

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
#issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
#issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"



#curl -d '{"webhook" : "https://altme.io/webhook", "contact_email" :"thierry@gmail.io"}'  -H "Content-Type: application/json" -X POST https://talao.co/sandbox/op/beacon/verifier/api/create/over13
# curl -H "X-API-KEY: 123456" -X GET http://192.168.0.66:50000/tezotopia/membershipcard/123

def init_app(app,red, mode) :
    app.add_url_rule('/tezotopia/membershipcard/<id>',  view_func=tezotopia_endpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    return

async def tezotopia_endpoint(id, red, mode): 
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
            if presentation['verifiableCredential']['credentialSubject']['type'] == 'TezosAssociatedAddress' :
                tezos_address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
                credential['credentialSubject']['associatedAddress']['blockchainTezos'] = tezos_address
                credential['credentialSubject']['offers']['analytics'] = "https://talao.co/analytics/" + tezos_address
            elif presentation['verifiableCredential']['credentialSubject']['type'] == 'Over13' :
                credential['credentialSubject']['ageRange'] = "13+"
        
        if credential['credentialSubject'].get('ageRange') != "13+" :
            logging.warning('Over 13 not available')
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
        metadata = {
            "name":"Tezotopia Membership",
            "symbol":"ALTMESBT",
            "creators":["Altme.io","did:web:altme.io:did:web:app.altme.io:issuer"],
            "decimals":"0",
            "displayUri":"ipfs://QmPUQZUP3aB44JFCgjj7a7PtB4yng8LhA9KE7UySDosRir",
            "publishers":["compell.io"],
            "minter": "KT1JwgHTpo4NZz6jKK89rx3uEo9L5kLY1FQe",
            "rights": "No License / All Rights Reserved",
            "artifactUri": "ipfs://QmPUQZUP3aB44JFCgjj7a7PtB4yng8LhA9KE7UySDosRir",
            "description":"During the next 365 days, when you will MINT an NFT on Tezotopia Starbase or buy a DROPS on Tezotopia Marketplace you will immediately receive a cashback on the Tezos blockchain address associated to this card. Please, use the same Tezos address to play on Tezotopia as the one you associated to this card. ID: Tezotopia Membership Card",
            "thumbnailUri": "ipfs://QmPUQZUP3aB44JFCgjj7a7PtB4yng8LhA9KE7UySDosRir",
            "is_transferable":False,
            "shouldPreferSymbol":False
        }
        try : 
            metadata_ipfs = add_dict_to_ipfs(metadata, "sbt:" + credential['id'] , mode)
            print("metadata ipfs = ", metadata_ipfs)
            if not metadata_ipfs :
                metadata_url = "ipfs://" + metadata_ipfs
                issue_sbt(tezos_address, metadata_url)
                print('issue sbt')
        except :
            print("code failed")
        
        # send credential to wallet        
        return jsonify(signed_credential)


def issue_sbt(address, metadata_ipfs_url) :
    url = 'https://altme-api.dvl.compell.io/mint'
    headers = {
                    "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "transfer_to" : address,
        "ipfs_url" : metadata_ipfs_url
    }
    resp = requests.post(url, data=data, headers=headers)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused, SBT not sent %s", resp.status_code)
    else :
        logging.info("SBT sent")
    return
 

def add_dict_to_ipfs(data_dict, name, mode) :
	api_key = mode.pinata_api_key
	secret = mode.pinata_secret_api_key
	headers = {'Content-Type': 'application/json',
				'pinata_api_key': api_key,
               'pinata_secret_api_key': secret}
	data = { 'pinataMetadata' : {'name' : name}, 'pinataContent' : data_dict}
	try :
		response = requests.post('https://api.pinata.cloud/pinning/pinJSONToIPFS', data=json.dumps(data), headers=headers)
	except :
		return None
	return response.json()['IpfsHash']