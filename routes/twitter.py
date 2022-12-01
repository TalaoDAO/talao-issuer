from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from components import message
import requests
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
from urllib.parse import urlencode
import didkit

OFFER_DELAY = timedelta(seconds= 10*60)
CODE_DELAY = timedelta(seconds= 180)
QRCODE_DELAY = 60

issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
issuer_did = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"


def init_app(app,red, mode) :
    app.add_url_rule('/twitter',  view_func=twitter_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/twitter/endpoint/<id>',  view_func=twitter_enpoint, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/twitter/stream',  view_func=twitter_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/twitter/end',  view_func=twitter_end, methods = ['GET', 'POST'])
    return


def twitter_qrcode(mode) :
    session['is_connected'] = True
    id = str(uuid.uuid1())
    qr_code = mode.server + "twitter/endpoint/" + id +'?' + urlencode({'issuer' : issuer_did})
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri' : qr_code })
    return render_template('twitter/twitter_qrcode.html',
                                url=qr_code,
                                id=id,
                                deeplink_altme=deeplink_altme)

   
async def twitter_enpoint(id, red):
    credential = json.load(open('./verifiable_credentials/TwitterAccount.jsonld', 'r'))
    credential["issuer"] = issuer_did 
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
    if request.method == 'GET': 
        # make an offer  
        credential_manifest = json.load(open('./credential_manifest/twitter_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['id'] = "urn:uuid:random"
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
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form['subject_id']
        presentation = json.loads(request.form['presentation'])
        address = presentation['verifiableCredential']['credentialSubject']['associatedAddress']
        #address = "tz1VgTYvEpxTgsnvySy6BmQiqaL1vgfBUzAB"
        #address = "tz1LMChSoDrZK8fFYmewVYnYe7q6tn43zFQs"
        url = "https://api.tzprofiles.com/" + address
        r = requests.get(url)
        if not 199<r.status_code<300 :
            logging.error("API call rejected %s", r.status_code)
            data = json.dumps({"id" : id, "check" : "failed"})
            red.publish('twitter', data)
            return jsonify('Server failed'), 500

    # treatment of API data
        tzprofiles_result = r.json()
        if not tzprofiles_result :
            logging.warning('TzProfiles not found')
            data = json.dumps({"id" : id, "check" : "not_found"})
            red.publish('twitter', data)
            return jsonify('TzProfile not found'), 404
        for data in tzprofiles_result :
            for vc in data :
                try :
                    credential['credentialSubject']['sameAs'] = json.loads(vc)['credentialSubject']['sameAs']
                    credential['evidence'] = json.loads(vc)['evidence']
                except :
                    pass
        if not credential['credentialSubject'].get('sameAs') :
            logging.warning('TzProfiles not found')
            data = json.dumps({"id" : id, "check" : "not_found"})
            red.publish('twitter', data)
            return jsonify('TzProfile not found'), 404
        # signature 
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
            }
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        if not signed_credential :         # send event to client agent to go forward
            logging.error('credential signature failed')
            data = json.dumps({"id" : id, "check" : "failed"})
            red.publish('twitter', data)
            return jsonify('Server failed'), 500
        # Success : send event to client agent to go forward
        data = json.dumps({"id" : id, "check" : "success"})
        red.publish('twitter', data)
        return jsonify(signed_credential)
 

def twitter_end() :
    if not session.get('is_connected') :
        return redirect ('/twitter')
    if request.args['followup'] == "success" :
        message = _('Great ! you have now a proof of ownership of your Twitter account.')
    elif request.args['followup'] == 'expired' :
        message = _('Sorry ! session expired.')
    elif request.args['followup'] == 'not_found' :
        message = 'Sorry ! your profile is not registered on Tezos Profiles.'
    else :
        message = _('Sorry ! there is a server problem, try again later.')
    session.clear()
    return render_template('twitter/twitter_end.html', message=message)


# server event
def twitter_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('twitter')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)