
import json
from flask import request, jsonify, render_template, session, redirect, Response
from flask_qrcode import QRcode
import didkit
import environment
import uuid
import logging
import requests
from urllib.parse import urlencode


ISSUER_KEY = json.load(open("keys.json", "r"))['talao_Ed25519_private_key']
TOKEN_LIFE = 60*60 # 1 heure

SUPPORTED_ADDRESS = ['TezosAssociatedAddress', 'BinanceAssociatedAddress']
SUPPORTED_CHAIN = ['binance', 'tezos']
URL_MAIN = "https://ssi-sbt-altme-bnb-main.osc-fr1.scalingo.io/"
URL_TEST = "https://ssi-sbt-altme-bnb-test.osc-fr1.scalingo.io/"

TEST = False


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
  "minter": "Meranti",
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


def test(test, mode) : 
    url = URL_TEST if test else URL_MAIN
    secret = mode.meranti_test if test else mode.meranti_main  
    return url, secret

def init_app(app,red, mode) :
    
    # for wallet
    app.add_url_rule('/verifier/defi/endpoint/<chain>/<stream_id>', view_func=verifier_endpoint, methods = ['POST', 'GET'], defaults={'mode': mode, 'red' : red})
    
    # for user mint
    app.add_url_rule('/defi/nft', view_func=defi_nft_binance, methods = ['GET'],  defaults={'mode': mode})
    app.add_url_rule('/defi/nft/binance', view_func=defi_nft_binance, methods = ['GET'],  defaults={'mode': mode})
    app.add_url_rule('/nft/defi', view_func=defi_nft_binance, methods = ['GET'],  defaults={'mode': mode})
    
    app.add_url_rule('/defi/nft/tezos', view_func=defi_nft_tezos, methods = ['GET'],  defaults={'mode': mode})

    app.add_url_rule('/defi/nft/stream',  view_func=defi_nft_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/defi/nft/end',  view_func=defi_nft_end, methods = ['GET', 'POST'])

    # for admin
    #app.add_url_rule('/verifier/defi/burn/<address>', view_func=burn_nft, methods = ['GET'])
    app.add_url_rule('/verifier/defi/has/<address>', view_func=has_nft, methods = ['GET'],  defaults={'mode': mode})
    app.add_url_rule('/verifier/defi/info/<id>', view_func=info_nft, methods = ['GET'],  defaults={'mode': mode})
    return


def defi_nft_binance(mode) :
    stream_id = str(uuid.uuid1())
    session['is_connected'] = True
    session['chain'] = 'binance'
    link = mode.server + 'verifier/defi/endpoint/binance/' + stream_id 
    deeplink =  mode.deeplink_altme + 'app/download?' + urlencode({'uri' : link })
    if not request.MOBILE:
        return render_template(
            'NFT/bnb.html',
            url=deeplink,
            deeplink_altme=deeplink,
            stream_id=stream_id
        )
    else :
        return render_template(
            'NFT/bnb_mobile.html',
            url=link,
            deeplink_altme=deeplink,
            stream_id=stream_id
        )


def defi_nft_tezos(mode) :
    stream_id = str(uuid.uuid1())
    session['is_connected'] = True
    session['chain'] = 'tezos'
    link = mode.server + 'verifier/defi/endpoint/tezos/' + stream_id 
    deeplink =  mode.deeplink_altme + 'app/download?' + urlencode({'uri' : link })
    if not request.MOBILE:
        return render_template(
            'NFT/tezos.html',
            url=deeplink,
            deeplink_altme=deeplink,
            stream_id=stream_id)
    else :
        return render_template(
            'NFT/tezos_mobile.html',
            url=link,
            deeplink_altme=deeplink,
            stream_id=stream_id)
    

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


def burn_nft(address, chain, mode) :
    """
    Binance
    """
    url, key = test(TEST, mode)
    url = url + 'burn'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-API-KEY" : key,
        "X-BLOCKCHAIN" : chain.upper()
    }
    data = {
        "address_for" : address,
    }
    resp = requests.post(url, data=data, headers=headers)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused, SBT not sent %s with reason = %s", resp.status_code, resp.reason)
        return jsonify({'burn' : False})
    return jsonify({'burn' : True})


def does_nft_exist(address, chain, mode) :
    url, key = test(TEST, mode)
    url = url + 'has/'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-API-KEY" : key,
        "X-BLOCKCHAIN" : chain.upper()
    }
    resp = requests.get(url + address, headers=headers)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused")
        return
    return resp.json()['has_token']


def has_nft(address, chain, mode) :
    url, key = test(TEST, mode)
    url = url + 'has/'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-API-KEY" : key,
        "X-BLOCKCHAIN" : chain.upper()
    }
    resp = requests.get(url + address, headers=headers)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused")
        return
    return jsonify(resp.json())


def info_nft(id, chain, mode) :
    """
    curl --location --request GET ‘https://ssi-sbt.osc-fr1.scalingo.io/id/0’
    """
    url, key = test(TEST, mode)
    url = url + 'id/'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-API-KEY" : key,
        "X-BLOCKCHAIN" : chain.upper()
    }
    
    resp = requests.get(url + id, headers=headers)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused")
        return
    return jsonify(resp.json())
  

def issue_nft(chain: str, address: str, metadata: dict, credential_id: str, mode: environment.currentMode) -> bool:
    """
    issue NFT with merenti smart contract on Binance

    curl --location --request POST ‘https://ssi-sbt.osc-fr1.scalingo.io/mint’ \
    --header ‘Content-Type: application/x-www-form-urlencoded’ \
    --header 'X-BLOCKCHAIN: BINANCE'\
    --header 'X-API-KEY' : hhhhh'\
    --data-urlencode ‘transfer_to=0xCdcc3Ae823F05935f0b9c35C1054e5C144401C0a’ \
    --data-urlencode ‘ipfs_url=ipfs://QmRmmqEFCeCtgyp6xdwHGCKjMcEiQUqA8Q76kP9diN1s5F’
    """
    metadata_ipfs = add_to_ipfs(metadata, "nft:" + credential_id , mode)
    if not metadata_ipfs :
        logging.error("pinning service failed")
        return
    url, key = test(TEST, mode)
    url = url + 'mint'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-API-KEY" : key,
        "X-BLOCKCHAIN" : chain.upper()
    }
    data = {
        "transfer_to" : address,
        "ipfs_url" : "ipfs://" + metadata_ipfs
    }
    logging.info('url de mint = %s', url)
    resp = requests.post(url, data=data, headers=headers)
    if 199<resp.status_code<300 :
        data = {"count" : "1" , "chain" : chain }
        requests.post(mode.server + 'counter/nft/update', data=data)
        return True
    else :
        logging.warning("Get access refused, NFT not mint %s with reason = %s", resp.status_code, resp.reason)
        return


def mint_nft(credential_id:str, address: str, chain:str, mode) -> bool:
    """
    mint NFT for one token received
    manage return issue
    """
    if chain == 'binance' :
        metadata = metadata_binance
    else :
        metadata = metadata_tezos
    metadata['identifier'] = credential_id
    return issue_nft(chain, address, metadata, "defi:" + chain + ":" + metadata['identifier'], mode)


async def verifier_endpoint(chain, stream_id, mode, red):
    """
    wallet endpoint of the verifier
    difference is that a token is passed as an argument in the wallet call 
    """
    if request.method == 'GET':
        pattern = {
            "type": "VerifiablePresentationRequest", 
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": [
                        {
                            "example" : {"type" : "DefiCompliance"} # DefiCompliance
              }]}
            ]
        }
        pattern['query'][0]['credentialQuery'].append({"example" : {"type" : chain.capitalize() + "AssociatedAddress"}})
        pattern['challenge'] = str(uuid.uuid1())
        pattern['domain'] = mode.server
        red.setex(stream_id,  180, json.dumps(pattern))
        return jsonify(pattern)
    else :
        try :
            my_pattern = json.loads(red.get(stream_id).decode())
            challenge = my_pattern['challenge']
            domain = my_pattern['domain']
        except :
            logging.error('red decode failed')
            data = json.dumps({"stream_id" : stream_id, "check" : "expired"})
            red.publish('defi_nft', data)
            return jsonify("URL not found"), 400
        red.delete(stream_id)
        presentation = json.loads(request.form['presentation'])
        # check authentication
        response_challenge = presentation['proof']['challenge']
        response_domain = presentation['proof']['domain']
        verifiable_credential_list = presentation['verifiableCredential']
        if response_domain != domain or response_challenge != challenge :
            logging.warning('challenge or domain failed')
            data = json.dumps({"stream_id" : stream_id, "check" : "failed"})
            red.publish('defi_nft', data)
            return jsonify('Credentials refused'), 400
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
                    return jsonify('Credentials refused'), 400
                else :
                    credential_id = vc['id']
                    logging.info("credential Id = %s", credential_id)
        
        if not address or not credential_id :
            logging.warning("Blockchain not supported")
            data = json.dumps({"stream_id" : stream_id, "check" : "failed"})
            red.publish('defi_nft', data)
            return jsonify("ok"), 400
        
        # test if NFT already exists for this address and chain
        if not  does_nft_exist(address, chain, mode) :
            # mint
            if not mint_nft(credential_id, address, chain, mode) :
                logging.warning("NFT mint failed")
                data = json.dumps({"stream_id" : stream_id, "check" : "failed"})
                red.publish('defi_nft', data)
                return jsonify('ok'), 400
            else :
                logging.info("NFT mint succeed")
                data = json.dumps({"stream_id" : stream_id, "check" : "success"})
                red.publish('defi_nft', data)
                return jsonify("ok")
        else :
            data = json.dumps({"stream_id" : stream_id, "check" : "already_exists"})
            red.publish('defi_nft', data)
            logging.info("The compliance NFT alreday exist")
            return jsonify("ok")


def defi_nft_end() :
    if not session.get('is_connected') :
        return redirect ('https://altme.io')
    if request.args['check'] == "success" :
        message = 'Great ! you have now a NFT as a proof of DeFi compliance.'
    elif request.args['check'] == 'expired' :
        message = 'Sorry ! session expired.'
    elif request.args['check'] == 'already_exists' :
        message = 'An NFT already exists.'
    else :
        message = 'Sorry ! there is a server problem, try again later.'
    chain = session['chain']
    session.clear()
    return render_template('NFT/defi_nft_end.html', message=message, chain=chain)


# server event
def defi_nft_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('defi_nft')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
