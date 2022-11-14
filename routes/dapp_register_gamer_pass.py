from flask import render_template, request, jsonify, Response, redirect, session
import uuid 
import json

def init_app(app,red, mode) :
    app.add_url_rule('/register_gamer_pass',  view_func=dapp_use_case, methods = ['GET', 'POST'])
    app.add_url_rule('/register_gamer_pass_1',  view_func=dapp_use_case_1, methods = ['GET', 'POST'])
    app.add_url_rule('/register_gamer_pass_2',  view_func=dapp_use_case_2, methods = ['GET', 'POST'])
    app.add_url_rule('/register_gamer_pass_3',  view_func=dapp_use_case_3, methods = ['GET', 'POST'])
    app.add_url_rule('/register_gamer_pass_3_1',  view_func=dapp_use_case_3_1, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/register_gamer_pass_4',  view_func=dapp_use_case_4, methods = ['GET', 'POST'])
    
    app.add_url_rule('/register_gamer_pass/webhook',  view_func=dapp_use_case_webhook, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/register_gamer_pass/stream',  view_func=dapp_use_case_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    global payload_over13, payload_download_gamer_pass, payload_account
    if mode.myenv == 'aws':
        payload_over13 = 'I confirm i am over 13 years old #https://talao.co/sandbox/op/beacon/verifier/lhvnwdhczp?id='
        payload_download_gamer_pass =  'Get your Gamer Pass ! #https://talao.co/sandbox/op/beacon/zbsjclrass?id='
        payload_account = "I want to associate another account #https://talao.co/sandbox/op/beacon/verifier/wfzovnsjrg?id="
    else :
        payload_over13 = 'I confirm i am over 13 years old #http://192.168.0.65:3000/sandbox/op/beacon/verifier/nebmmcdkva?id='
        payload_download_gamer_pass = 'Get your Gamer Pass ! #http://192.168.0.65:3000/sandbox/op/beacon/mmibrdplfm?id='
        payload_account = 'I want to associate another account #http://192.168.0.65:3000/sandbox/op/beacon/verifier/yusbbdwdnv?id='
    return

# intro
def dapp_use_case():
    if request.method == "GET" :
        session.clear()
        session['id'] = str(uuid.uuid1())
        return render_template('./gamer_pass/register_gamer_pass_0.html',
                             id = session['id'])
    else :
        print("return")
        return redirect('/register_gamer_pass_1?id=' + session['id'])


# over13
def dapp_use_case_1():
    if not session.get('id') :
        return jsonify('Unauthorized'), 404
    if request.method == "GET" :
        global payload_over13
        return render_template('./gamer_pass/register_gamer_pass_1.html',
                             id = session['id'],
                             payload_over13 = payload_over13 + session['id'])
    else :
        return redirect('/register_gamer_pass_2?id=' + session['id'])


# account 1
def dapp_use_case_2():
    if not session.get('id') :
        return jsonify('Unauthorized'), 404
    if request.method == "GET" :
        global payload_account
        return render_template('./gamer_pass/register_gamer_pass_2.html',
                             id = session['id'],
                             payload_account = payload_account + session['id'])
    else :
        return redirect('/register_gamer_pass_3?id=' + session['id'])

# account 2
def dapp_use_case_3():
    if not session.get('id') :
        return jsonify('Unauthorized'), 404
    if request.method == "GET" :
        global payload_account
        return render_template('./gamer_pass/register_gamer_pass_3.html',
                             id = session['id'],
                             payload_account = payload_account + session['id'])
    else :
        return redirect('/register_gamer_pass_3_1?id=' + session['id'])


# altname  2
def dapp_use_case_3_1(red):
    if not session.get('id') :
        return jsonify('Unauthorized'), 404
    if request.method == "GET" :
        global payload_account
        return render_template('./gamer_pass/register_gamer_pass_3_1.html',
                             id = session['id'],
                             payload_account = payload_account + session['id'])
    else :
        if request.form.get('altName') :
            red.setex(session['id'] + "_alternateName", 180, request.form['altName'])
        return redirect('/register_gamer_pass_4?id=' + session['id'])


# Gamer Pass
def dapp_use_case_4():
    if not session.get('id') :
        return jsonify('Unauthorized'), 404
    if request.method == "GET" :
        global payload_download_gamer_pass
        return render_template('./gamer_pass/register_gamer_pass_4.html',
                             id = session['id'],
                             payload_download_gamer_pass = payload_download_gamer_pass + session['id'])
    else :
        return jsonify('ok')


def dapp_use_case_webhook(red) :
    data = request.get_json()
    
    if data['event'] == 'VERIFICATION' :    
        if  "Over13" in data["vc_type"] :
            event_data = json.dumps({ 'id' : data['id'],
                                    "over13" : 'verified'})
            red.publish('use_case', event_data)
            red.setex(data['id'] + "_over13", 180, "Yes")
            return jsonify('ok')
        
        if  "Over18" in data["vc_type"] :
            event_data = json.dumps({ 'id' : data['id'],
                                    "over18" : 'verified'})
            red.publish('use_case', event_data)
            red.setex(data['id'] + "_over18", 180, "Yes")
            return jsonify('ok')

        if  "TezosAssociatedAddress" in data["vc_type"] :
            event_data = json.dumps({ 'id' : data['id'],
                                    "account" : 'verified'})
            red.publish('use_case', event_data)
            try :
                address = list()
                address.append(red.get(data['id'] +'_TezosAssociatedAddress').decode())
                address.append(data['associatedAddress'])
                red.setex(data['id'] + "_TezosAssociatedAddress", 180, json.dumps(address))
            except :
                red.setex(data['id'] + "_TezosAssociatedAddress", 180, data['associatedAddress'])
            return jsonify('ok')

        if  "EthereumAssociatedAddress" in data["vc_type"] :
            event_data = json.dumps({ 'id' : data['id'],
                                    "account" : 'verified'})
            red.publish('use_case', event_data)
            try :
                address = list()
                address.append(red.get(data['id'] +'_EthereumAssociatedAddress').decode())
                address.append(data['associatedAddress'])
                red.setex(data['id'] + "_EthereumAssociatedAddress", 180, json.dumps(address))
            except :
                red.setex(data['id'] + "_EthereumAssociatedAddress", 180, data['associatedAddress'])
            return jsonify('ok')
    
    if data['event'] == 'ISSUANCE' :
        credentialSubject = dict()
        try :
            credentialSubject['over13'] = red.get(data['id'] +'_over13').decode()
        except :
            print('No credential Over13')
        try :
            credentialSubject['over18'] = red.get(data['id'] +'_over18').decode()
        except :
            print('No credential Over18')
        try :
            credentialSubject['tezosAddress'] = red.get(data['id'] +'_TezosAssociatedAddress').decode()
        except :
            print('No Tezos Address')
        try :
            credentialSubject['ethereumAddress'] = red.get(data['id'] +'_EthereumAssociatedAddress').decode()
        except :
            print('No Ethereum Address')
        try :
            credentialSubject['alternateName'] = red.get(data['id'] + "_alternateName").decode()
        except :
            print('No alternate name')

        credentialSubject.update({
            "type" : "BloometaPass",
            "issuedBy" : {"name" : "Bloometa"}
        })
        print("data sent back to Issuer = ", credentialSubject)
        return jsonify(credentialSubject)

    if data['event'] == 'SIGNED_CREDENTIAL' :
        event_data = json.dumps({"gamer_pass" : 'issued',
                                    'id' : data['id'],
                                    'data' : json.dumps(data)})
        red.publish('use_case', event_data)
        return jsonify('ok')

    return jsonify('ok')

def dapp_use_case_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('use_case')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
