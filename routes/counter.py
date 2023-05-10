from flask import jsonify, request
import json
import requests


def init_app(app) :
    app.add_url_rule('/counter/get',  view_func=counter_get, methods = ['GET'])
    app.add_url_rule('/counter/update',  view_func=counter_update, methods = ['POST'])
    return


def counter_get() :
    """
    to get the values 
    """
    return json.load(open("counter.json", "r"))


def counter_update():
    """
    this allows teh wallet to update the counter json file

    with a simple request request 
    # update counter
    data = {"vc" : "bloometa" , "count" : "1" }
    requests.post(mode.server + 'counter/update', data=data)
    """
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
    # send data to slack
    url = "https://hooks.slack.com/services/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"
    payload = {
        "channel": "#issuer_counter",
        "username": "issuer",
        "text": json.dumps(counter),
        "icon_emoji": ":ghost:"
        }
    data = {
        'payload': json.dumps(payload)
    }
    r = requests.post(url, data)
    print("status code slack = ", r.status_code)
    return jsonify('ok')

