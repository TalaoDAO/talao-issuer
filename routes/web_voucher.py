from flask import jsonify, request, render_template, session, Response
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
    app.add_url_rule('/voucher/<voucher_id>',  view_func=voucher_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/voucher/offer/<voucher_id>/<id>',  view_func=voucher_offer, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/voucher/stream',  view_func=voucher_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/voucher/end',  view_func=voucher_end, methods = ['GET', 'POST'])
    return


def add_voucher(my_voucher, mode) :
    url = "https://talao.co/analytics/api/v1"
    headers = {
        'accept' : 'application/json',
        'ANALYTICS-KEY' : mode.analytics_key
    }
    data = {"voucher" : my_voucher}
    r = requests.put(url, data =data, headers=headers)
    if not 199<r.status_code<300 :
        logging.error("API call rejected %s", r.status_code)
        # TODO
        return True
    else :
        logging.info("API call accepted %s", r.status_code)
        return True


def voucher_qrcode(voucher_id, mode) :
    try :
        json.loads(open('./verifiable_credentials/TezVoucher_' + voucher_id + '.jsonld', 'r').read())
    except :
        return jsonify('Voucher not found')
    url = mode.server + "voucher/offer/" + voucher_id +'/' + session.sid +'?' + urlencode({'issuer' : DID})
    deeplink = mode.deeplink + 'app/download?' + urlencode({'uri' : url })
    return render_template('voucher/voucher_qrcode.html',
                                url=url,
                                deeplink=deeplink)
   

async def voucher_offer(voucher_id, id, red, mode):
    """ Endpoint for wallet
    """
    try :
        credential = json.loads(open('./verifiable_credentials/TezVoucher_' + voucher_id + '.jsonld', 'r').read())
    except :
        logging.error("voucher not found")
        data = json.dumps({"url_id" : id, "check" : "failed"})
        red.publish('voucher', data)
        return jsonify('server error')

    credential["issuer"] = DID
    credential['id'] = "urn:uuid:random"
    credential['credentialSubject']['id'] = "did:wallet"
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 30)).isoformat() + "Z"
    filename = "./credential_manifest/tezotopia_voucher_credential_manifest.json"
    with open(filename, "r") as f:
        credential_manifest = f.read()
    credential_manifest = json.loads(credential_manifest)
    if request.method == 'GET': 
        # make an offer  
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)
    elif request.method == 'POST': 
        # sign credential
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form.get('subject_id', 'unknown DID')
        # TODO check DID and get data associated address from verifiable_presentation attribute
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": vm_tz1
            }
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                key_tz1)
        if not signed_credential :
            logging.error('credential signature failed')
            data = json.dumps({"url_id" : id, "check" : "failed"})
            red.publish('voucher', data)
            return jsonify('server error')
        # update the voucher data base
        if not add_voucher(signed_credential, mode) :
            data = json.dumps({"url_id" : id, "check" : "failed"})
            red.publish('voucher', data)
            return jsonify('server error')
        # send event to client agent to go forward
        data = json.dumps({"url_id" : id, "check" : "success"})
        red.publish('voucher', data)
        return jsonify(signed_credential)
 

def voucher_end() :
    if request.args['followup'] == "success" :
        message = _('Great ! you have now a Tezotopia voucher to get rewards.')
    elif request.args['followup'] == 'expired' :
        message = _('Sorry, session expired.')
    else :
        message = _('Sorry, server problem, try again later.')
    return render_template('voucher/voucher_end.html', message=message)


# server event push 
def voucher_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('voucher')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
