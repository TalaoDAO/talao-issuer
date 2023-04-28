
from flask import jsonify
import json
import logging
logging.basicConfig(level=logging.INFO)

def init_app(app) :
    app.add_url_rule('/credential-manifest/polygonid/<type>',  view_func=credential_manifest, methods = ['GET'])
    return

def credential_manifest(type) :
    try : 
        credential_manifest = json.load(open('./credential_manifest/polygonid/' + type.lower() + '.json', 'r'))
    except :
        credential_manifest = json.load(open('./credential_manifest/polygonid/default.json', 'r'))
    return jsonify(credential_manifest)