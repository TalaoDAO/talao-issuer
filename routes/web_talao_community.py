from flask import jsonify, request, render_template, Response, redirect
import json
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import requests
from jwcrypto import jwt, jwk
import sys
from datetime import datetime, timedelta

def init_app(app,red, mode) :
    app.add_url_rule('/tc',  view_func=talao_community, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/talao_community',  view_func=talao_community, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/tc/webhook',  view_func=webhook, methods = ['POST'])
    app.add_url_rule('/tc/callback',  view_func=callback, methods = ['GET', 'POST'])
    return

public_key =  {'kty': 'RSA', 'kid': '123', 'n': 'pPocyKreTAn3YrmGyPYXHklYqUiSSQirGACwJSYYs-ksfw4brtA3SZCmA2sdAO8a2DXfqADwFgVSxJFtJ3GkHLV2ZvOIOnZCX6MF6NIWHB9c64ydrYNJbEy72oyG_-v-sE6rb0x-D-uJe9DFYIURzisyBlNA7imsiZPQniOjPLv0BUgED0vdO5HijFe7XbpVhoU-2oTkHHQ4CadmBZhelCczACkXpOU7mwcImGj9h1__PsyT5VBLi_92-93NimZjechPaaTYEU2u0rfnfVW5eGDYNAynO4Q2bhpFPRTXWZ5Lhnhnq7M76T6DGA3GeAu_MOzB0l4dxpFMJ6wHnekdkQ', 'e': 'AQAB'}


def add_talao_community(my_talao_community, mode) :
    # my_talao_community is a json stringexi
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
   

def talao_community(mode) :
    if mode.myenv != 'aws':
        link = "http://192.168.0.123:3000/sandbox/op/issuer/shftylibxa"
    else :
        link = 'https://talao.co/sandbox/op/issuer/fwkpatoulq'
    return redirect (link)
   

def webhook() :
    # Get user data from access_token received (optional)
    access_token = request.headers["Authorization"].split()[1]
    key = jwk.JWK(**public_key)
    try :
        ET = jwt.JWT(key=key, jwt=access_token)
    except :
        logging.error("signature error")
        sys.exit()
    user_data = json.loads(ET.claims)
    logging.info('user data received from platform = %s', user_data)
    credential = {
    "expirationDate" : (datetime.now() + timedelta(days= 30)).isoformat() + "Z",
    "credentialSubject": 
        {
            "id": "",
            "type": "TalaoCommunity",
            "walletNotation" : "Gold",
            "talaoAccount": "0x83E0481C1844Ed257efE1147218C125832F10236",
            "offers" : [{
                "startDate" : "2022-08-01T19:55:00Z",
                "endDate" : "2022-12-31T19:55:00Z",
                "duration" : "30",
                "category" : "discounted_coupon",
                "analytics" : "",
                "userGuide" : "",
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
                    "blockchainTezos" : user_data['vp']['verifiableCredential']['credentialSubject']['associatedAddress'],
                    "blockchainEthereum" : "",
                    "blockchainPolygon" : ""
            }
         }
    }
    return(jsonify(credential))


def callback() :
    message = _('Great ! you have now Talao community card to get rewards.')
    return render_template('talao_community/talao_community_end.html', message=message)
