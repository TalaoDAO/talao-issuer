
from flask import jsonify, request, render_template, Response, redirect
import json
from datetime import datetime
import uuid
import logging
from urllib.parse import urlencode
import oidc
import sqlite3
import requests

logging.basicConfig(level=logging.INFO)

API_LIFE = 1000
ACCESS_TOKEN_LIFE = 3000
GRANT_LIFE = 1000
C_NONCE_LIFE = 1000
CRYPTOGRAPHIC_SUITES = ['ES256K','ES256','ES384','ES512','RS256', 'EdDSA']
DID_METHODS = ['did:ebsi', 'did:key']
GRANT_TYPE_SUPPORTED = [ 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'authorization_code']
issuer_key = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"

def init_app(app,red, mode) :
    # endpoint for application
    app.add_url_rule('/oidc4vci/kyc',  view_func=oidc4vci_kyc_landing_page, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/oidc4vci/kyc/issuer_stream',  view_func=oidc4vci_kyc_stream, methods = ['GET', 'POST'], defaults={'red' :red})
    app.add_url_rule('/oidc4vci/kyc/issuer_followup',  view_func=oidc4vci_kyc_followup, methods = ['GET'])
    
    # EBSI OIDC4VCI protocol with wallet
    app.add_url_rule('/oidc4vci/kyc/.well-known/openid-configuration', view_func=oidc4vci_kyc_openid_configuration, methods=['GET'], defaults={'mode' : mode})
    app.add_url_rule('/oidc4vci/kyc/authorize',  view_func=oidc4vci_kyc_authorize, methods = ['GET', 'POST'], defaults={'red' :red, 'mode' : mode})
    app.add_url_rule('/oidc4vci/kyc/token',  view_func=oidc4vci_kyc_token, methods = ['GET', 'POST'], defaults={'red' :red, 'mode' : mode})
    app.add_url_rule('/oidc4vci/kyc/credential',  view_func=oidc4vci_kyc_credential, methods = ['GET', 'POST'], defaults={'red' :red})
    return


def get_identity(passbase_key, mode) :
    url = "https://api.passbase.com/verification/v1/identities/" + passbase_key
    logging.info("API call url = %s", url)
    headers = {
        'accept' : 'application/json',
        'X-API-KEY' : mode.passbase
    }
    r = requests.get(url, headers=headers)
    logging.info("status code = %s", r.status_code)
    if not 199<r.status_code<300 :
        logging.error("API call rejected %s", r.status_code)
        return None
    # treatment of API data
    identity = r.json()
    return identity


def get_passbase_data_from_did(did) :
    """
    return the last one
    """
    conn = sqlite3.connect('passbase_check.db')
    c = conn.cursor()
    data = { "did" : did}
    c.execute("SELECT status, key, created FROM webhook WHERE did = :did", data)
    check = c.fetchall()
    logging.info("check = %s", check)
    conn.close()
    if len(check) == 1 :
        return check[0]
    try :
        return check[-1]
    except :
        return None


def build_credential(did,mode) :
    file_path = './verifiable_credentials/VerifiableId.json'
    credential = json.load(open(file_path))
    try :
        (status, passbase_key, created) = get_passbase_data_from_did(did) # client_id = did
    except :
        return "kyc_not_done"
    if status != "approved" :
        return 'not_approved'
    identity = get_identity(passbase_key, mode)
    if not identity :
        return "identity_not_found"
    credential['credentialSubject']['birthPlace'] = identity['resources'][0]['datapoints'].get('place_of_birth', 'Not indicated')
    credential['credentialSubject']['birthDate'] = identity['resources'][0]['datapoints'].get('date_of_birth', "Not indicated")
    credential['credentialSubject']['givenName'] = identity['owner']['last_name']
    credential['credentialSubject']['familyName'] = identity['owner']['first_name']
    credential['credentialSubject']['gender'] = identity['resources'][0]['datapoints'].get('sex', "Not indicated")
    credential['credentialSubject']['authority'] = identity['resources'][0]['datapoints'].get('authority', "Not indicated")
    credential['credentialSubject']['nationality'] = identity['resources'][0]['datapoints'].get('nationality', "Not indicated")
    credential['credentialSubject']['expiryDate'] = identity['resources'][0]['datapoints'].get('date_of_expiry', "Not indicated")
    credential['credentialSubject']['issueDate'] = identity['resources'][0]['datapoints'].get('date_of_issue', "Not indicated")
    return credential


def manage_error(error, error_description, status=400) :
    """
    # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    logging.warning(error_description)   
    payload = {
        'error' : error,
        'error_description' : error_description
    }
    headers = {
        'Cache-Control' : 'no-store',
        'Content-Type': 'application/json'}
    return {'response' : json.dumps(payload), 'status' : status, 'headers' : headers}


def oidc4vci_kyc_openid_configuration(mode):
    """
    OpenId configuration endpoint 

    Attention for EBSI "types" -> credentialSchema.id of data model

    https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html
    
    ATTENTION new OIDC4VCI standard is https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
    """
    return jsonify(oidc_configuration(mode))


def oidc_configuration(mode):
    """
    https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html
    ATTENTION new OIDC4VCI standard is https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
    Credential Manifest is included
    Wallet Rendering is included 
    """    
    # credential manifest
    #https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-server-metadata
    file_path = './credential_manifest/verifiableid_credential_manifest.json'
    credential_manifest = [json.load(open(file_path))]
    credential_manifest[0]['issuer']['id'] = issuer_did
    credential_manifest[0]['issuer']['name'] = 'KYC issuer Altme'
    
    #credential supported
    credential_supported = [{
        'format': 'jwt_vc',
        'id': 'VerifiableId',
        'types':  'https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z22ZAMdQtNLwi51T2vdZXGGZaYyjrsuP1yzWyXZirCAHv',
        'display': [
            {
                'name': 'Altme',
                'locale': 'en-US',
            }
        ],
        'cryptographic_binding_methods_supported': [
            'did'
        ],
        'cryptographic_suites_supported': CRYPTOGRAPHIC_SUITES
    }]
    
    openid_configuration = {
        'credential_issuer': mode.server + 'oidc4vci/kyc',
        'authorization_endpoint':  mode.server + 'oidc4vci/kyc/authorize',
        'token_endpoint': mode.server + 'oidc4vci/kyc/token',
        'credential_endpoint': mode.server + 'oidc4vci/kyc/credential',
        'pre-authorized_grant_anonymous_access_supported' : False,
        'subject_syntax_types_supported': DID_METHODS,
        'credential_supported' : credential_supported,
        'credential_manifests' : credential_manifest,
    }
    return openid_configuration


# initiate endpoint with QRcode
def oidc4vci_kyc_landing_page(red, mode) :
    """
    https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html

    openid://initiate_issuance
    ?issuer=http%3A%2F%2F192.168.0.65%3A3000%2Fsandbox%2Febsi%2Fissuer%2Fhqplzbjrhg
    &credential_type=Pass
    &op_state=40fd65cf-98ba-11ed-957d-512a313adf23
    """    
    stream_id = str(uuid.uuid1())
    # Option 1 https://api-conformance.ebsi.eu/docs/wallet-conformance/issue
    pre_authorized_code = stream_id
    #pre_authorized_code = False
    url_data  = { 
        'issuer' : mode.server +'oidc4vci/kyc',
        'credential_type'  : 'https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z22ZAMdQtNLwi51T2vdZXGGZaYyjrsuP1yzWyXZirCAHv',
        'op_state' : stream_id, #  op_stat 
    }
    # if pre authorized code flow, we alreday know the user
    if  pre_authorized_code :
        url_data["pre-authorized_code"] = pre_authorized_code
        url_data[ "user_pin_required"] = False
        # TODO get the DID of the user
        user_did = 'did:key:z6MktuwLvSUYeJeWJgDvJ6RftTvyRSoNRGXxckeE44qTKkKV'
        code_data = {
            'credential_type' : 'https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z22ZAMdQtNLwi51T2vdZXGGZaYyjrsuP1yzWyXZirCAHv',
            'format' : 'jwt_vc',
            'vc' : build_credential(user_did, mode),
            'stream_id' : stream_id
            }
        red.setex(pre_authorized_code, GRANT_LIFE, json.dumps(code_data))

    #  https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-pre-authorized-code-flow

    url = 'openid://initiate_issuance?' + urlencode(url_data)
    logging.info('qrcode = %s', url)
    openid_configuration  = json.dumps(oidc_configuration(mode), indent=4)
    deeplink_talao = mode.deeplink_talao + 'app/download/ebsi?' + urlencode({'uri' : url })
    deeplink_altme = mode.deeplink_altme + 'app/download/ebsi?' + urlencode({'uri' : url})

    return render_template(
        'oidc4vci/kyc.html',
        openid_configuration = openid_configuration,
        url_data = json.dumps(url_data,indent = 6),
        url=url,
        deeplink_altme=deeplink_altme,
        deeplink_talao=deeplink_talao,
        stream_id=stream_id,
        page_title='Issuer of Verifiable ID in jwt format with Passbase',
        page_subtitle=' ',
        page_description='',
        title='title',
        qrcode_message='qrcode_message',
        landing_page_url='landing_page_url',
        privacy_url='privacy_url',
        terms_url='terms_url',
        mobile_message='mobile_message',
        page_background_color = '',
        page_text_color = '',
        qrcode_background_color = '',
    )

def oidc4vci_kyc_authorize(red, mode) :
    """
    https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-credential-authorization-re

    my_request = {
        'scope' : 'openid',
        'client_id' : 'did:ebsi:z454654654654',
        'response_type' : 'code',
        'authorization_details' : json.dumps([{'type':'openid_credential',
                        'credential_type': credential_type,
                        'format':'jwt_vc'}]),
        'redirect_uri' :  ngrok + '/callback',
        'state' : '1234', # generated by wallet 
        'op_state' : 'mlkmlkhm' # generated by issuer
        }

    """
    def authorization_error_response(error, error_description, stream_id, red) :
        """
        for internal function call 
        https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-authentication-error-respon
        https://www.rfc-editor.org/rfc/rfc6749.html#page-26
        """
        # front channel follow up 
        if stream_id  :
            event_data = json.dumps({'stream_id' : stream_id})           
            red.publish('issuer_oidc4vci', event_data)
        logging.warning(error_description)
        resp = {
            'error_description' : error_description,
            'error' : error
        }
        return redirect(redirect_uri + '?' + urlencode(resp))

    logging.info("authorization request received = %s", request.args)
    try :
        client_id = request.args['client_id']
        redirect_uri = request.args['redirect_uri']
    except :
        return jsonify('invalid_request'), 400

    op_state = request.args.get('op_state')
    if not op_state :
        logging.warning("op_state is missing")
        return jsonify('invalid_request'), 400
        
    try :
        scope = request.args['scope']
    except :
        return authorization_error_response("invalid_request", "scope is missing", op_state, red)
    
    try :
        response_type = request.args['response_type']
    except :
        return authorization_error_response("invalid_request", "reponse_type is missing", op_state, red)
    
    try :
        credential_type = json.loads(request.args['authorization_details'])[0]['credential_type']
    except :
        return authorization_error_response("invalid_request", "credential_type is missing", op_state, red)
    
    try :
        format = json.loads(request.args['authorization_details'])[0]['format']
    except :
        return authorization_error_response("invalid_request", "format is missing", op_state, red)

    if scope != 'openid' :
        return authorization_error_response("invalid_scope", "unsupported scope", op_state, red)

    if response_type != 'code' :
        return authorization_error_response("unsupported_response_type", "unsupported response type", op_state, red)

    if format not in ['jwt_vc', 'jwt_vc_json'] :
        return authorization_error_response("invalid_request", "unsupported format", op_state, red)

    # TODO Manage login and get vc for this user
    client_id = 'did:key:z6MktuwLvSUYeJeWJgDvJ6RftTvyRSoNRGXxckeE44qTKkKV'
    credential = build_credential(client_id,mode) 
    if credential == "kyc_not_found" :
        logging.error("Check has not been done")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : "Identification not done"
                        })
        red.publish('passbase', data)
        return jsonify ('KYC has not been done'),412
    elif credential == "not_approved" :
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : "Identification not approved"
                        })
        red.publish('passbase', data)
        return jsonify('KYC not approved'), 412
    elif credential == "identity_not_found" :
        logging.warning("Identity does not exist")
        data = json.dumps({
                    'id' : id,
                    'check' : 'failed',
                    'message' : "Identity does not exist"
                        })
        red.publish('passbase', data)
        return jsonify('Identity does not exist'), 412
    else :
        pass

    # Code creation
    code = str(uuid.uuid1())
    code_data = {
        'credential_type' : credential_type,
        'format' : format,
        'vc' : credential,
        'stream_id' : op_state
    }
    #logging.info('code data = %s', code_data)
    red.setex(code, GRANT_LIFE, json.dumps(code_data))    
    resp = {'code' : code}
    if request.args.get('state') :
        resp['state'] = request.args['state']
    return redirect(redirect_uri + '?' + urlencode(resp))


# token endpoint
def oidc4vci_kyc_token(red, mode) :
    """
    https://datatracker.ietf.org/doc/html/rfc6749#section-5.2

    https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-token-endpoint
    """
    logging.info("token endpoint request = %s", json.dumps(request.form))
    try :
        grant_type =  request.form['grant_type']
    except :
        return Response(**manage_error("invalid_request", "Request format is incorrect"))
    
    if grant_type not in GRANT_TYPE_SUPPORTED :
        return Response(**manage_error("invalid_grant", "Grant type not supported"))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code' :
        try :
            code = request.form['pre-authorized_code']
        except :
            try :
                code = request.form['pre-authorised_code']
            except :
                logging.warning('pre authorized code is missing')
                return Response(**manage_error("invalid_grant", "Request format is incorrect"))
    else:
        try :
            code = request.form['code']
        except :
            logging.warning('code from authorization server is missing')
            return Response(**manage_error("invalid_request", "Request format is incorrect"))    
    try :
        code_data = json.loads(red.get(code).decode())
    except :
        return Response(**manage_error("invalid_grant", "Grant code expired"))     
    
    # token response
    access_token = str(uuid.uuid1())
    c_nonce = str(uuid.uuid1())
    endpoint_response = {
        'access_token' : access_token,
        'c_nonce' : c_nonce,
        'token_type' : 'Bearer',
        'expires_in': ACCESS_TOKEN_LIFE
    }
    access_token_data = {
        'access_token' : access_token,
        'c_nonce' : c_nonce,
        'format' : code_data['format'],
        'credential_type' :  code_data['credential_type'],
        'vc' : code_data['vc'],
        'stream_id' : code_data['stream_id']
    }
    red.setex(access_token, ACCESS_TOKEN_LIFE,json.dumps(access_token_data))
    
    headers = {
        'Cache-Control' : 'no-store',
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)
 

# credential endpoint
def oidc4vci_kyc_credential(red) :
    """
    https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html#name-credential-endpoint
    
    https://api-conformance.ebsi.eu/docs/specs/credential-issuance-guidelines#credential-request
    """
    logging.info("credential endpoint request")
    # Check access token
    try :
        access_token = request.headers['Authorization'].split()[1]
    except :
        return Response(**manage_error("invalid_token", "Access token not passed in request header"))
    try :
        access_token_data = json.loads(red.get(access_token).decode())
    except :
        return Response(**manage_error("invalid_token", "Access token expired")) 
    
    # Check request 
    try :
        result = request.json
        credential_type = result['type']
        proof_format = result['format']
        proof_type  = result['proof']['proof_type']
        proof = result['proof']['jwt']
    except :
        return Response(**manage_error("invalid_request", "Invalid request format 2")) 
    
    if credential_type != access_token_data['credential_type'] :
        return Response(**manage_error("unsupported_credential_type", "The credential type is not supported")) 
    if proof_format != 'jwt_vc' :
        return Response(**manage_error("unsupported_credential_format", "The proof format is not supported")) 
    if proof_type != 'jwt' :
        return Response(**manage_error("invalid_or_missing_proof", "The proof type is not supported")) 

    # Get holder pub key from holder wallet and verify proof
    logging.info("proof of owbership = %s", proof)
    try :
        oidc.verif_token(proof, access_token_data['c_nonce'])
    except Exception as e :
        logging.error("verif proof error = %s", str(e))
        return Response(**manage_error("invalid_or_missing_proof", str(e))) 
    
    # Build JWT VC and sign VC
    proof_payload=oidc.get_payload_from_token(proof)
    credential = access_token_data['vc']
    credential['id'] = str(uuid.uuid1())
    credential['credentialSubject']['id'] = proof_payload['iss']
    credential['issuer']= issuer_did
    credential['issued'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['validFrom'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential_signed = oidc.sign_jwt_vc(credential, issuer_vm , issuer_key, issuer_did, proof_payload['iss'], access_token_data['c_nonce'])
    logging.info("credential sent = %s", credential_signed)
    # send event to front to go forward callback and send credential to wallet
    data = json.dumps({'stream_id' : access_token_data['stream_id']})
    red.publish('issuer_oidc4vci', data)

    # Transfer VC
    payload = {
        'format' : proof_format,
        'credential' : credential_signed,
        'c_nonce': str(uuid.uuid1()),
        'c_nonce_expires_in': C_NONCE_LIFE
    }
    headers = {
        'Cache-Control' : 'no-store',
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(payload), headers=headers)
  

def oidc4vci_kyc_followup():  
    return redirect ('https://altme.io')
    
    
# server event push for user agent EventSource
def oidc4vci_kyc_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('issuer_oidc4vci')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()  
    headers = { 'Content-Type' : 'text/event-stream',
                'Cache-Control' : 'no-cache',
                'X-Accel-Buffering' : 'no'}
    return Response(event_stream(red), headers=headers)



