import time  
import math
from jwcrypto import jwk, jwt
import json
from flask import Flask, request, jsonify
from flask_qrcode import QRcode
import didkit
import os
import environment
import redis
import uuid
import base64
import logging
import requests
import hashlib

ISSUER_KEY = json.load(open("keys.json", "r"))['talao_Ed25519_private_key']
TOKEN_LIFE = 15*24*60*60
SUPPORTED_ADDRESS = ['TezosAssociatedAddress', 'EthereumAssociatedAddress', 'BinanceAssociatedAddress']
SUPPORTED_CHAIN = ['binance', 'tezos']


metadata_tezos = {
  "name": "DeFi compliance proof",
  "symbol": "DEFI",
  "creators": [
    "Altme.io",
    "did:web:altme.io:did:web:app.altme.io:issuer"
  ],
  "decimals": "0",
  "identifier": "",
  "displayUri": "ipfs://QmUDYRnEsCv4vRmSY57PC6wZyc6xqGfZecdSaZmo2wnzDF",
  "publishers": ["Altme"],
  "minter": "to be defined",
  "rights": "No License / All Rights Reserved",
  "artifactUri": "ipfs://QmUDYRnEsCv4vRmSY57PC6wZyc6xqGfZecdSaZmo2wnzDF",
  "description": "This NFT is a proof of your DeFi compliance. It is not transferable.You can use it when you need to prove your comliance with services that have already adopted the verifiable and decentralized identity system.",
  "thumbnailUri": "ipfs://QmZP3od8tRFUhH7yNVuD3zYPGyLZSpp6a6At6kcW2MjsLD",
  "is_transferable": False,
  "shouldPreferSymbol": False
}


metadata_binance = {
    "name": "DeFi compliance proof",
    "symbol": "DEFI",
    "description": "This NFT is a proof of your KYC-AML compliance. It is not transferable. You can use it when you need to prove your comliance with DeFi services that have adopted decentralized identity to protect user data.",
    "image": "ipfs://QmUDYRnEsCv4vRmSY57PC6wZyc6xqGfZecdSaZmo2wnzDF",
    "identifier": "",
}


app = Flask(__name__)
app.secret_key = "NFT DeFi"
qrcode = QRcode(app)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'local'
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)


def init_app(app,red, mode) :
    # for DefI site
    app.add_url_rule('/verifier/defi/get_link', methods = ['POST', 'GET'], view_func=get_link)
    
    # for wallet
    app.add_url_rule('/verifier/defi/endpoint', view_func=verifier_endpoint, methods = ['POST', 'GET'], defaults={'mode': mode, 'red' : red})
    
    # for admin
    app.add_url_rule('/verifier/defi/burn/<address>', view_func=burn_nft, methods = ['GET'])
    app.add_url_rule('/verifier/defi/has/<address>', view_func=has_nft, methods = ['GET'])
    return


def add_to_ipfs(data_dict: dict, name: str, mode: environment.currentMode) -> str :
    """
    add metadata file to IPFS
    """
    api_key = mode.pinata_api_key
    secret = mode.pinata_secret_api_key
    headers = {
        'Content-Type': 'application/json',
		'pinata_api_key': api_key,
        'pinata_secret_api_key': secret}
    data = {
        'pinataMetadata' : {
            'name' : name
        },
        'pinataContent' : data_dict
    }
    r = requests.post('https://api.pinata.cloud/pinning/pinJSONToIPFS', data=json.dumps(data), headers=headers)
    if not 199<r.status_code<300 :
        logging.warning("POST access to Pinatta refused")
        return None
    else :
	    return r.json()['IpfsHash']


def issue_nft_tezos(address: str, metadata: dict, credential_id: str, mode: environment.currentMode) -> bool:
    """
    issue NFT with compellio smart contract on Tezos
    """
    metadata_ipfs = add_to_ipfs(metadata, "nft:" + credential_id , mode)
    if not metadata_ipfs :
        logging.error("pinning service failed")
        return
    url = 'https://altme-api.dvl.compell.io/mint'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "transfer_to" : address,
        "ipfs_url" : "ipfs://" + metadata_ipfs
    }
    resp = requests.post(url, data=data, headers=headers)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused, SBT not sent %s", resp.status_code)
        return
    data = {"count" : "1" , "chain" : "tezos" }
    requests.post(mode.server + 'counter/nft/update', data=data)
    return True


def burn_nft(address) :
    url = 'https://ssi-sbt.osc-fr1.scalingo.io/burn'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "address_for" : address,
    }
    resp = requests.post(url, data=data, headers=headers)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused, SBT not sent %s with reason = %s", resp.status_code, resp.reason)
        return jsonify({'burn' : False})
    return jsonify({'burn' : True})


def has_nft(address) :
    url = 'https://ssi-sbt.osc-fr1.scalingo.io/has/'
    resp = requests.get(url + address)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused")
        return
    return jsonify(resp.json())


def issue_nft_binance(address: str, metadata: dict, credential_id: str, mode: environment.currentMode) -> bool:
    """
    issue NFT with merenti smart contract on Binance

    curl --location --request POST ‘https://ssi-sbt.osc-fr1.scalingo.io/mint’ \
    --header ‘Content-Type: application/x-www-form-urlencoded’ \
    --data-urlencode ‘transfer_to=0xCdcc3Ae823F05935f0b9c35C1054e5C144401C0a’ \
    --data-urlencode ‘ipfs_url=ipfs://QmRmmqEFCeCtgyp6xdwHGCKjMcEiQUqA8Q76kP9diN1s5F’
    """
    metadata_ipfs = add_to_ipfs(metadata, "nft:" + credential_id , mode)
    if not metadata_ipfs :
        logging.error("pinning service failed")
        return
    url = 'https://ssi-sbt.osc-fr1.scalingo.io/mint'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "transfer_to" : address,
        "ipfs_url" : "ipfs://" + metadata_ipfs
    }
    resp = requests.post(url, data=data, headers=headers)
    if 199<resp.status_code<300 :
        data = {"count" : "1" , "chain" : "binance" }
        requests.post(mode.server + 'counter/nft/update', data=data)
        return True
    elif resp.status_code == 430 :
        logging.info("NFT already minted")
        return True
    else :
        logging.warning("Get access refused, NFT not mint %s with reason = %s", resp.status_code, resp.reason)
        return
   


def generate_token(chain: str) -> str:
    """
    generate an anonymous token with an expîration fixed date every 15 days from 01 jan 1970
    """
    if chain not in SUPPORTED_CHAIN :
        return
    signer_key = jwk.JWK(**ISSUER_KEY) 
    header = {
      'typ' :'JWT',
      'kid': "did:web:app.altme.io:issuer#key-1",
      'alg': 'EdDSA'
    }
    payload = {
      'iss' : "did:web:app.altme.io:issuer",
      'exp': (math.floor(time.time()/TOKEN_LIFE) + 1) * TOKEN_LIFE,
      'chain' : chain
    }  
    token = jwt.JWT(header=header,claims=payload, algs=['EdDSA'])
    token.make_signed_token(signer_key)
    return token.serialize()


def verif_token(token: str) -> None:
    """
    verification of the jwt token signature
    raise error if problem
    """
    a = jwt.JWT.from_jose_token(token)
    a.validate(jwk.JWK(**ISSUER_KEY))
    return


def get_data_from_token(data: str,  token: str) -> any:
  """
  return  attribute of token
  data = chain, exp
  """
  payload = token.split('.')[1]
  payload += "=" * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
  return json.loads(base64.urlsafe_b64decode(payload).decode())[data]


def mint_nft(credential_id:str, address: str, chain:str) -> bool:
    """
    mint NFT for one token received
    manage return issue
    """
    if chain == "tezos"  : 
        metadata_tezos['identifier'] = credential_id
        logging.info('mint DeFi NFT on Tezos') 
        return issue_nft_tezos(address, metadata_tezos, "defi:tezos:" + metadata_tezos['identifier'], mode)
    elif chain == "binance" :
        metadata_binance['identifier'] = credential_id
        logging.info('mint DeFi NFT on Binance')
        return issue_nft_binance(address, metadata_binance, "defi:binance:" + metadata_binance['identifier'], mode)
    else :
        logging.warning('Blockchain not supported for this DeFi NFT mint')
        return 


def get_link():
    """
    This the first call customer side to get its link
    curl https://issuer.talao.co/verifier/defi/get_link -H "api-key":<your_api_key> -H "client_id":<your_client_id>
    returns {"link": <link>} 200
   
    """
    client_secret = request.headers.get('api-key')
    client_id = request.headers.get('client_id')
    # TODO check the client database
    chain = request.headers.get('chain', 'binance')
    token = generate_token(chain)
    if not token :
        return jsonify({"Bad request"}), 400
    link = mode.server + 'verifier/defi/endpoint?token=' + token
    return jsonify({"link": link})


async def verifier_endpoint(mode, red):
    """
    wallet endpoint of the verifier
    difference is that a token is passed as an argument in the wallet call 
    """
    # one takes as the session id the wallet IP hash
    m = hashlib.sha256()
    m.update(request.remote_addr.encode())
    session_id = m.hexdigest()
    token = request.args.get('token')
    if not token :
        return jsonify ('Unauthorized'), 401
    try :
        verif_token(token)
        chain = get_data_from_token('chain', token)
        exp = get_data_from_token('exp', token)
    except Exception as e: 
        logging.error('verif token failed %s', e )
        return jsonify ('Unauthorized'), 401
    if time.time() > exp :
        logging.warning('DeFi token expired')
        return jsonify ('Unauthorized'), 401
    
    if request.method == 'GET':
        pattern = {
            "type": "VerifiablePresentationRequest",
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": [
                        {
                            "example" : {"type" : "DefiCompliance"}
              }]}]}
        pattern['query'][0]['credentialQuery'].append({"example" : {"type" : chain.capitalize() + "AssociatedAddress"}})
        pattern['challenge'] = str(uuid.uuid1())
        pattern['domain'] = mode.server
        red.setex(session_id,  60, json.dumps(pattern))
        return jsonify(pattern)
    else :
        try :
            my_pattern = json.loads(red.get(session_id).decode())
            challenge = my_pattern['challenge']
            domain = my_pattern['domain']
        except :
            logging.error('red decode failed')
            return jsonify("URL not found"), 404
        presentation = json.loads(request.form['presentation'])
        # check authentication
        response_challenge = presentation['proof']['challenge']
        response_domain = presentation['proof']['domain']
        verifiable_credential_list = presentation['verifiableCredential']
        if response_domain != domain or response_challenge != challenge :
            logging.warning('challenge or domain failed')
            return jsonify('Credentials refused'), 412
        # check presentation signature
        presentation_result = json.loads(await didkit.verify_presentation(request.form['presentation'], '{}'))
        if presentation_result['errors']:  
            logging.warning('presentation signature failed')
        else :
            logging.info('presentation signature is Ok')
        # get address from VC
        address = credential_id = str()
        for vc in verifiable_credential_list :
            if vc['credentialSubject']['type'] in SUPPORTED_ADDRESS :
                address = vc['credentialSubject']['associatedAddress']
                logging.info("address = %s", address)
            elif vc['credentialSubject']['type'] == 'DefiCompliance' :
                if vc['credentialSubject']['amlComplianceCheck'] != 'Succeeded' :
                    logging.warning('VC compliance is Failed')
                    return jsonify('Credentials refused'), 412
                else :
                    credential_id = vc['id']
                    logging.info("credential Id = %s", credential_id)
        if not address or not credential_id :
            logging.warning("Blockchain not supported %s %s", address, credential_id)
            return jsonify("Blockchain not supported"), 412
        # mint
        if not mint_nft(credential_id, address, chain) :
            logging.error("NFT DeFi mint failed")
            return jsonify('NFT DeFi mint failed'), 412
        logging.info('NFT has been minted for %s', chain)
        return jsonify("ok")



