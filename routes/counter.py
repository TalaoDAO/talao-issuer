from flask import jsonify, request
import json
import requests
import logging
logging.basicConfig(level=logging.INFO)

VC_LIST = [
    "emailpass", "phonepass", "agerange",
    "over18", "over13", "over15", "over21", "over50", "over65", "verifiableid",
    "liveness", "diploma", "chainborn", "nationality",
    "tezotopia", "bloometa", "twitter", "defi",
    "tezosassociatedaddress", "binanceassociatedaddress", "fantomassociatedaddress",
    "polygonassociatedaddress", "ethereumassociatedaddress" 
]


def init_app(app, mode):
    app.add_url_rule('/counter/get',  view_func=counter_get, methods=['GET'])
    app.add_url_rule('/counter/update',  view_func=counter_update, methods=['POST'], defaults={"mode": mode})
    app.add_url_rule('/counter/nft/get',  view_func=counter_nft_get, methods=['GET'])
    app.add_url_rule('/counter/nft/update',  view_func=counter_nft_update, methods=['POST'], defaults={"mode": mode})
    return


def counter_get():
    """
    to get the values 
    """
    return json.load(open("counter.json", "r"))


def counter_update(mode):
    """
    this allows the wallet to update the counter json file

    with a simple request request 
    # update counter
    data = {"vc" : "bloometa" , "count" : "1" }
    requests.post(mode.server + 'counter/update', data=data)
    """
    vc = request.form.get('vc').lower()
    if vc not in VC_LIST:
        logging.warning("%s not in VC LIST", vc)
        return jsonify('Bad request'), 400
    count = request.form.get('count')
    if not count or not vc :
        logging.error("counter error")
        return jsonify('Bad request'), 400
    counter = json.load(open("counter.json", "r"))
    credential_list = list(counter.keys())
    for credential in credential_list:
        if credential == vc :
            counter[credential] += int(count)
            counter["total"] += int(count)
            break
    counter_file = open("counter.json", "w")
    counter_file.write(json.dumps(counter))
    counter_file.close()

    # send data to slack
    url = mode.slack_url
    payload = {
        "channel": "#issuer_counter",
        "username": "issuer",
        "text": "New VC is " + vc + " " + json.dumps(counter),
        "icon_emoji": ":ghost:"
        }
    data = {
        'payload': json.dumps(payload)
    }
    r = requests.post(url, data=data)
    return jsonify('ok')



"""
For NFT

"""

def counter_nft_get() :
    """
    to get the values 
    """
    return json.load(open("counter_defi.json", "r"))


def counter_nft_update(mode):
    """
    this allows the verifier to update the counter json file

    with a simple request request 
    # update counter
    data = {"count" : "1" , "chain" : "binance" }
    requests.post(mode.server + 'counter/nft/update', data=data)
    """
    count = request.form.get('count')
    that_chain = request.form.get('chain')
    if not that_chain or not count :
        return jsonify('update refused'), 404
    counter = json.load(open("counter_defi.json", "r"))
    chain_list = list(counter.keys())
    for chain in chain_list :
        if chain == that_chain :
            counter[chain] += int(count)
            counter["total"] += int(count)
            break
    counter_file = open("counter_defi.json", "w")
    counter_file.write(json.dumps(counter))
    counter_file.close()

    # send data to slack
    url = mode.slack_nft_url
    payload = {
        "channel": "#defi_nft_counter",
        "username": "DeFi_verifier",
        "text": json.dumps(counter),
        "icon_emoji": ":ghost:"
        }
    data = {
        'payload': json.dumps(payload)
    }
    r = requests.post(url, data=data)
    return jsonify('ok')

