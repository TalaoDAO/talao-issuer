from flask import jsonify, request, render_template, session, Response, render_template_string
import json
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _
from urllib.parse import urlencode
import didkit
import requests

OFFER_DELAY = timedelta(seconds= 30)
CODE_DELAY = timedelta(seconds= 180)
QRCODE_DELAY = 30


key_tz1 = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
vm_tz1 = vm = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du#blockchainAccountId"
DID =  "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"


def init_app(app,red, mode) :
    app.add_url_rule('/talao_community',  view_func=talao_community_qrcode, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/talao_community/offer/<talao_community_id>/<id>',  view_func=talao_community_offer, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/talao_community/stream',  view_func=talao_community_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/talao_community/end',  view_func=talao_community_end, methods = ['GET', 'POST'])
    return


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
   


def talao_community_qrcode(red, mode) :
    if request.method == 'GET' :
        return render_template('talao_community/landing_page.html', 
                                )
    id = str(uuid.uuid1())
    url = mode.server + 'talao_community/offer/' + id +'?' + urlencode({'issuer' : DID})
    deeplink = mode.deeplink + 'app/download?' + urlencode({'uri' : url })
    return render_template('talao_community/talao_community_qrcode.html',
                                url=url,
                                id=id,
                                deeplink=deeplink)
   

async def talao_community_offer(id, red, mode):
    """ Endpoint for wallet
    """
    talao_community = json.loads(open('./verifiable_credentials/TalaoCommunity.jsonld', 'r').read())   
    talao_community["issuer"] = DID
    talao_community['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    talao_community['expirationDate'] =  (datetime.now() + timedelta(days= 30)).isoformat() + "Z"
    filename = "./credential_manifest/talaocommunity_credential_manifest_1.json"
    with open(filename, "r") as f:
        credential_manifest = f.read()
    credential_manifest = json.loads(credential_manifest)
    challenge = str(uuid.uuid1())
    if request.method == 'GET': 
        # make an offer  
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": talao_community,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "challenge" : challenge,
            "domain" : "tezotopia.talao.co",
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)
    elif request.method == 'POST': 
        # sign credential
        talao_community['id'] = "urn:uuid:" + str(uuid.uuid1())
        talao_community['credentialSubject']['id'] = request.form.get('subject_id', 'unknown DID')
        # TODO check DID and setup associated address from data received
        vp = json.loads(request.form.get('presentation'))
        talao_account = vp["verifiableCredential"]["credentialSubject"]["talaoAccount"]
        # TODO calculer le nombre de token Talao
        talao_community["credentialSubject"]["associatedAddress"]["blockchainTezos"] = vp["verifiableCredential"]["credentialSubject"]["blockchainTezos"]
        talao_community["credentialSubject"]["associatedAddress"]["blockchainEthereum"] = vp["verifiableCredential"]["credentialSubject"]["blockchainEthereum"]
        talao_community["credentialSubject"]["talaoAccount"] = talao_account
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": vm_tz1
            }
        signed_talao_community =  await didkit.issue_credential(
                json.dumps(talao_community),
                didkit_options.__str__().replace("'", '"'),
                key_tz1)
        if not signed_talao_community :
            logging.error('credential signature failed')
            data = json.dumps({"url_id" : id, "check" : "failed"})
            red.publish('talao_community', data)
            return jsonify('server error')
        # update the talao_community data base
        if not add_talao_community(signed_talao_community, mode) :
            data = json.dumps({"url_id" : id, "check" : "failed"})
            red.publish('talao_community', data)
            return jsonify('server error')
        # send event to client agent to go forward
        data = json.dumps({"url_id" : id, "check" : "success"})
        red.publish('talao_community', data)
        return jsonify(signed_talao_community)
 

def talao_community_end() :
    if request.args['followup'] == "success" :
        message = _('Great ! you have now a Tezotopia talao_community to get rewards.')
    elif request.args['followup'] == 'expired' :
        message = _('Sorry, session expired.')
    else :
        message = _('Sorry, server problem, try again later.')
    return render_template('talao_community/talao_community_end.html', message=message)


# server event push 
def talao_community_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('talao_community')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
