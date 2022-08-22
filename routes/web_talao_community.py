from flask import jsonify, request, render_template, redirect
import json
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import requests
from datetime import datetime, timedelta
import constante
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/f2be8a3bf04d4a528eb416566f7b5ad6"))
Talao_token_contract = '0x1D4cCC31dAB6EA20f461d329a0562C1c58412515'
#test_address = Web3.toChecksumAddress("0x5afa04fb1108ad9705526cf980a2d5122a5817fa")

def token_balance(address) :
    address = Web3.toChecksumAddress(address)
    contract = w3.eth.contract(Talao_token_contract,abi=constante.Talao_Token_ABI)
    raw_balance = contract.functions.balanceOf(address).call()
    balance=raw_balance//10**18
    return balance


def init_app(app,red, mode) :
    app.add_url_rule('/tc',  view_func=talao_community, methods = ['GET'])
    app.add_url_rule('/talao_community',  view_func=talao_community, methods = ['GET'])
    app.add_url_rule('/tc/webhook',  view_func=webhook, methods = ['POST'])
    app.add_url_rule('/tc/callback',  view_func=callback, methods = ['GET'])
    global link, client_secret
    if mode.myenv != 'aws':
        link = "http://192.168.0.123:3000/sandbox/op/issuer/shftylibxa"
        client_secret = "2652f832-1bbb-11ed-9222-d9af830f0c58"
    else :
        link = 'https://talao.co/sandbox/op/issuer/fwkpatoulq'
        client_secret = "7dca6002-1c77-11ed-9407-0a1628958560"
    return


def add_talao_community(my_talao_community, mode) :
    # my_talao_community is a json string
    my_talao_community = json.loads(my_talao_community)
    my_talao_community = json.dumps(my_talao_community, ensure_ascii=True)

    url = "https://talao.co/analytics/api/newvoucher"
    headers = {
        'key' : mode.analytics_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    r = requests.post(url, data=my_talao_community, headers=headers)
    if not 199<r.status_code<300 :
        logging.error("API call rejected %s", r.status_code)
        return False
    else :
        logging.info("API call accepted %s", r.status_code)
        return True
   

def talao_community() :
    global client_secret
    return redirect (link)
   

def webhook() :
    if request.headers.get("key") != client_secret :
        return jsonify("Forbidden"), 403
   
    data = request.get_json()
    if data['event'] == 'ISSUANCE' :   
        vp_list = data['vp']
        for vp in vp_list :
            presentation = json.loads(vp)
            if presentation['verifiableCredential']['credentialSubject']['type'] == "TezosAssociatedAddress" :
                tezos_associated_address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
            if presentation['verifiableCredential']['credentialSubject']['type'] == "TalaoAssociatedAddress" :
                talao_associated_address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']

        balance =  token_balance(talao_associated_address)
        logging.info("balance = %s", balance)
        if balance > 100 :
            notation = "Iron"
        if balance > 500 :
            notation = "Gold"
        if balance > 2000 :
            notation = "Silver"
        if balance > 5000 :
            notation = "Platinium"

        credential = {
            "expirationDate" : (datetime.now().replace(microsecond=0) + timedelta(days= 180)).isoformat() + "Z",
            "credentialSubject": 
            {
                "id": "",
                "type": "TalaoCommunity",
                "walletNotation" : notation,
                "talaoAccount": talao_associated_address,
                "offers" : [{
                    "startDate" : "2022-08-01T19:55:00Z",
                    "endDate" : "2022-12-31T19:55:00Z",
                    "duration" : "180",
                    "category" : "discounted_coupon",
                    "analytics" : "https://talao.co/analytics/" + tezos_associated_address,
                    "userGuide" : "https://altme.io",
                    "benefit" : {
                        "discount" : "25%"
                    },    
                    "offeredBy": {
                        "logo": "ipfs://QmZmdndUVRoxiVhUnjGrKnNPn8ah3jT8fxTCLMnAzRAFFZ",
                        "name": "Gif Games",
                        "description" : "Gaming platform of Tezotopia",
                        "website" : "https://tezotopia.com"
                    }
                }],
                "associatedAddress" : {
                    "blockchainTezos" : tezos_associated_address
                }
            }
        }
        return(jsonify(credential))
    
    if data['event'] == 'RECEIPT' :
        logging.info("credential issued = %s", data['vc'])
        return jsonify('ok')
 


def callback() :
    message = _('Great ! you have now Talao community card to get rewards.')
    return render_template('talao_community/talao_community_end.html', message=message)
