from flask import jsonify, request,  Response, render_template, session, redirect
import requests
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
import didkit
from components import message
from urllib.parse import urlencode


OFFER_DELAY = timedelta(seconds= 180)

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"


def init_app(app,red, mode) :
    app.add_url_rule('/bloometa',  view_func=bloometa, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/bloometa/membershipcard/<id>',  view_func=bloometa_endpoint, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/bloometa/stream',  view_func=bloometa_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/bloometa/end',  view_func=bloometa_end, methods = ['GET', 'POST'])
    return


def send_data_to_bloometa(data, mode) :
    """
    curl -X POST \
        'https://bloometa.com/altme' \
        --header 'bloometa-issuer-key: 234465687-0591-4416-95c0-9b36b4d0e478' \
        --header 'Content-Type: application/json' \
        --data-raw '{
            "tezosAddress": ["tz1aDroxdCBaNtLFyxtcMP89vcUY2xRT4ND6"],
            "ethereumAddress": null,
            "polygonAddress": ["0x03817255659dc455079df516c5271b4046b2065b"],
            "binanceAddress": ["0x03817255659dc455079df516c5271b4046b2065b"],
            "fantomAddress": ["0x03817255659dc455079df516c5271b4046b2065b"],
            "email": "thierry.thevenet@talao.io",
            "device": "SM-A025G", 
            "systemVersion": "android",
        }'
    
    """
    url = 'https://bloometa.com/altme'
    headers = {
        'Content-Type' : 'application/json',
        'bloometa-issuer-key' : mode.bloometa_issuer_key     
    }
    r = requests.post(url, headers=headers, data=json.dumps(data))
    logging.info("Send data : status code = %s", r.status_code)
    if not 199<r.status_code<300 :
        logging.error("API call to Bloometa rejected %s", r.status_code)
        return
    else :
        logging.info('Data has been sent to Bloometa')
        return True


def bloometa(red, mode) :
    if request.method == 'GET':
        session['authenticated'] = True
        return render_template ('bloometa/bloometa.html')
    else :
        if not session.get('authenticated') :
            return redirect ('/bloometa')
        id =str(uuid.uuid1())
        data = {
            "alternateName" : request.form.get('alternateName'),
            "twitterAccount" : request.form.get('twitterAccount'),
            "discordAccount" : request.form.get('discordAccount')
        }
        logging.info('data = %s', data)
        red.setex(id, 360, json.dumps(data))
        url=mode.server + 'bloometa/membershipcard/' + id
        return render_template(
            'bloometa/qrcode.html',
            id =id,
            deeplink_altme= mode.deeplink_altme + 'app/download?' + urlencode({'uri' : url }),
            url=url
        )


async def bloometa_endpoint(id, red, mode):
    if request.method == 'GET':
        try :
            data = json.loads(red.get(id).decode())
        except :
            logging.error("redis get data failed")
            endpoint_response= {"error": "delay_expired"}
            headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
            return Response(response=json.dumps(endpoint_response), status=400, headers=headers)
        
        credential = json.load(open('./verifiable_credentials/BloometaPass.jsonld', 'r'))
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential["issuer"] = issuer_did 
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
        credential_manifest = json.load(open('./credential_manifest/bloometapass_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['credentialSubject']['id'] = "did:wallet"
        if data.get('alternateName') :
            credential['credentialSubject']['alternateName'] = data['alternateName']
        if data.get('twitterAccount') :
            credential['credentialSubject']['twitterAccount'] = data['twitterAccount']
        if data.get('discordAccount') :
            credential['credentialSubject']['discordAccount'] = data['discordAccount']
        red.setex(id, 360, json.dumps(credential))
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
        #try : 
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        #except :
        #    logging.error('credential signature failed')
        #    endpoint_response= {"error": "server_error"}
        #    headers = {'Content-Type': 'application/json',  "Cache-Control": "no-store"}
        #    return Response(response=json.dumps(endpoint_response), status=500, headers=headers)
       
        # update counter
        data = {"vc" : "bloometa" , "count" : "1" }
        requests.post(mode.server + 'counter/update', data=data)

        # call bloometa endpoint
        data = {
            'alternateName' :  credential['credentialSubject'].get('alternateName'),
            'twitterAccount' :  credential['credentialSubject'].get('twitterAccount'),
            'discordAccount' :  credential['credentialSubject'].get('discordAccount'),
            'tezosAddress' :  credential['credentialSubject'].get('tezosAddress'),
            'ethereumAddress' :  credential['credentialSubject'].get('ethereumAddress'),
            'polygonAddress' :  credential['credentialSubject'].get('polygonAddress'),
            'binanceAddress' :  credential['credentialSubject'].get('binanceAddress'),
            'fantomAddress' :  credential['credentialSubject'].get('fantomAddress'),
            'email' : email,
            'over18' : True
        }
        logging.info('data  = %s', data)
        send_data_to_bloometa(data, mode)

        # Success : send event to client agent to go forward
        data = json.dumps({"id" : id, "check" : "success"})
        red.publish('bloometa', data)
        message.message("Bloometa membership card issued ", "thierry@altme.io", credential['credentialSubject']['id'], mode)
        
        # send credential to wallet
        return jsonify(signed_credential)


def bloometa_end() :
    if not session.get('authenticated') :
        return redirect ('/bloometa')
    if request.args['followup'] == "success" :
        message = _('Great ! You have now your Bloometa card.')
    elif request.args['followup'] == 'expired' :
        message = _('Sorry ! Session expired.')
    else :
        message = _('Sorry ! There is a server problem, try again later.')
    session.clear()
    return render_template('bloometa/bloometa_end.html', message=message)


# server event
def bloometa_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('bloometa')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)