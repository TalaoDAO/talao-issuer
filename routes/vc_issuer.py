from flask import jsonify
import logging
import json

logging.basicConfig(level=logging.INFO)


def init_app(app, red, mode):
    app.add_url_rule('/.well-known/openid-configuration', view_func=openid_configuration, methods=['GET'], defaults={'mode': mode})
    return


def openid_configuration(mode):
    credential_manifest = {
        "id": "Identity_cards",
        "issuer": {
            "id": "uuid:0001",
            "name": "Altme issuer"
        },
        "output_descriptors": []
    }
    for cm in ['over18', 'over13', 'over15', 'over21', 'over50', 'over65', 'agerange']:
        over = json.loads(open("./credential_manifest/" + cm + "_credential_manifest.json", 'r').read())['output_descriptors'][0]
        credential_manifest["output_descriptors"].append(over)
    oidc = {
        "issuer": mode.server,
        "token_endpoint": mode.server + 'token',
        "credential_endpoint": mode.server + 'credential',
        "credential_manifest": credential_manifest,
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic"
        ]
    }
    return jsonify(oidc)

