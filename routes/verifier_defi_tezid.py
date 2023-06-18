import json
from flask import Flask, request, jsonify, render_template
from flask_qrcode import QRcode
import didkit
import uuid
import logging
from components import message
from urllib.parse import urlencode
from altme_on_chain import register_tezid


def init_app(app,red, mode) :  
    # for wallet
    app.add_url_rule('/verifier/defi/tezid/endpoint/<session_id>', view_func=verifier_defi_tezid_endpoint, methods = ['POST', 'GET'], defaults={'mode': mode, 'red' : red})
    # for user
    app.add_url_rule('/defi/tezid', view_func=defi_tezid, methods = ['GET'],  defaults={'mode': mode, 'red' : red})
    app.add_url_rule('/nft/tezid', view_func=defi_tezid, methods = ['GET'],  defaults={'mode': mode, 'red' : red})
    return


def defi_tezid(mode, red) :
    session_id = str(uuid.uuid1())
    link = mode.server + 'verifier/defi/tezid/endpoint/' + session_id
    deeplink =  mode.deeplink_altme + 'app/download?' + urlencode({'uri' : link })
    pattern = {
            "type": "VerifiablePresentationRequest",
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": [
                        {
                            "example" : {"type" : "DefiCompliance"}
                        },
                        {
                            "example" : {"type" : "TezosAssociatedAddress"}
                        }
              ]}
            ]
        }
    pattern['challenge'] = str(uuid.uuid1())
    pattern['domain'] = mode.server
    red.setex(session_id,  60, json.dumps(pattern))
    if not request.MOBILE:
        return render_template('tezid/tezos.html', url=link, deeplink_altme=deeplink)
    else :
        return render_template('tezid/tezos_mobile.html', url=link, deeplink_altme=deeplink)


async def verifier_defi_tezid_endpoint(session_id, mode, red):
    """
    wallet endpoint of the verifier
    difference is that a token is passed as an argument in the wallet call 
    """
    if request.method == 'GET':
        try :
            my_pattern = json.loads(red.get(session_id).decode())
        except :
            logging.error('red decode failed')
            return jsonify("URL not found"), 404
        return jsonify(my_pattern)
    else :
        try :
            my_pattern = json.loads(red.get(session_id).decode())
            challenge = my_pattern['challenge']
            domain = my_pattern['domain']
        except :
            logging.error('red decode failed')
            return jsonify("URL not found"), 404
        red.delete(session_id)
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
            if vc['credentialSubject']['type'] == 'TezosAssociatedAddress' :
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
            logging.warning("Process failed")
            return jsonify("Process failed"), 412
        
        # register in whitelist 
        if register_tezid(address, 'defi_compliance', "ghostnet", mode) :
            logging.info("address whitelisted for DeFi compliance %s", address)
            message.message("DeFi compliance address whitelisted", "thierry@altme.io", address, mode)
        else :
            logging.error("address NOT whitelisted for DeFi compliance %s", address)
        return jsonify("ok")



