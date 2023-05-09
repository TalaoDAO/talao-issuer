from flask import jsonify, request
import json
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import _


def init_app(app) :
    app.add_url_rule('/counter/get',  view_func=counter_get, methods = ['GET'])
    app.add_url_rule('/counter/update',  view_func=counter_update, methods = ['POST'])
    return

def counter_get() :
    return json.load(open("counter.json", "r"))

def counter_update():
    vc = request.form.get('vc')
    count = request.form.get('count')
    if not count or not vc :
        return jsonify('update refused'), 404
    counter = json.load(open("counter.json", "r"))
    credential_list = list(counter.keys())
    for credential in credential_list :
        if credential == vc :
            counter[credential] += int(count)
            counter["total"] += int(count)
            break
    counter_file = open("counter.json", "w")
    counter_file.write(json.dumps(counter))
    counter_file.close()
    return jsonify('ok')

