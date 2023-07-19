"""
Python 3.9 ++
didkit 0.3.0 get_version
"""
from flask import Flask, jsonify, session, request, render_template_string, render_template, redirect
from flask_qrcode import QRcode
from flask_session import Session
import didkit
import redis
import os
import sys
import json
from flask_babel import Babel, _, refresh
from datetime import timedelta
import markdown
import markdown.extensions.fenced_code
from components import message
from flask_session import Session
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
from flask_mobility import Mobility


# local dependencies
from routes import web_emailpass, web_phonepass, yoti, dapp_register_gamer_pass
from routes import tezotopia, twitter, chainborn, bloometa, oidc4vci_kyc, polygonid, counter
from routes import verifier_defi_nft, verifier_defi_tezid
import environment

import logging
logging.basicConfig(level=logging.INFO)

LANGUAGES = ['en', 'fr']

# Redis est utilisé pour stocker les données de session
red= redis.Redis(host='localhost', port=6379, db=0)

logging.info("python version : %s", sys.version)
logging.info("didkit version = %s", didkit.get_version())

# init
myenv = os.getenv('MYENV')
if not myenv :
   myenv='local'
mode = environment.currentMode(myenv)
app = Flask(__name__)
qrcode = QRcode(app)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'altme_issuer'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60) # session lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "issuer" + mode.password
app.jinja_env.globals['Version'] = "1.5.1"

# site X
app.config.update(
    OIDC_REDIRECT_URI = mode.server + 'callback', # your application redirect uri. Must not be used in your code
    SECRET_KEY = "lkjhlkjh" # your application secret code for session, random
)
babel = Babel(app)
Mobility(app)

"""
https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xiii-i18n-and-l10n
pybabel extract -F babel.cfg -o messages.pot .
pybabel update -i messages.pot -d translations -l fr
pybabel compile -d translations
"""
sess = Session()
sess.init_app(app)

# init routes 
web_emailpass.init_app(app, red, mode)
web_phonepass.init_app(app, red, mode)
#vc_issuer.init_app(app, red, mode)
#web_passbase.init_app(app, red, mode)
dapp_register_gamer_pass.init_app(app, red, mode)
yoti.init_app(app, red, mode)
tezotopia.init_app(app, red, mode)
twitter.init_app(app, red, mode)
chainborn.init_app(app, red, mode)
bloometa.init_app(app, red, mode)
oidc4vci_kyc.init_app(app, red, mode)
polygonid.init_app(app)
counter.init_app(app, mode)
verifier_defi_nft.init_app(app, red, mode)
verifier_defi_tezid.init_app(app, red, mode)


@app.errorhandler(500)
def error_500(e):
    message.message("Error 500 on issuer", 'thierry.thevenet@talao.io', str(e) , mode)
    return redirect('https://altme.io')


@babel.localeselector
def get_locale():
	if not session.get('language') :
		session['language'] = request.accept_languages.best_match(LANGUAGES)
	else :
		refresh()
	#return session['language']
	return "en"

																													
@app.route('/language', methods=['GET'], defaults={'mode': mode})
def user_language(mode) :
    #session['language'] = request.args['lang']
	session['language'] = "en"
	#refresh()
	#return redirect (request.referrer)
	return 'en'


"""
# Google universal link for jpma
@app.route('/.well-known/assetlinks.json' , methods=['GET']) 
def assetlinks(): 
    document = json.load(open('jpma_assetlinks.json', 'r'))
    return jsonify(document)


# Apple universal link for jpma
@app.route('/.well-known/apple-app-site-association' , methods=['GET']) 
def apple_app_site_association(): 
    document = json.load(open('jpma_apple-app-site-association.json', 'r'))
    return jsonify(document)
"""



@app.route('/md_file', methods = ['GET', 'POST'])
def md_file() :
	"""
	https://dev.to/mrprofessor/rendering-markdown-from-flask-1l41
	"""
	if request.args['file'] == 'privacy' :
		try :
			content = open('privacy_'+ session['language'] + '.md', 'r').read()
		except :
			content = open('privacy_en.md', 'r').read()
	
	elif request.args['file'] == 'terms_and_conditions' :
		try :
			content = open('cgu_'+ session['language'] + '.md', 'r').read()
		except :
			content = open('cgu_en.md', 'r').read()
	return render_template_string( markdown.markdown(content, extensions=["fenced_code"]))


@app.route('/company/', methods = ['GET', 'POST'])
def company() :
	""" mentions legales
	@app.route('/company')
	"""
	return render_template('company.html')


@app.route('/' , methods=['GET']) 
def test() :
   return jsonify("Hello")






### SITE X a retirer des que possible


# +18
client_metadata_18 = ClientMetadata(
        client_id='dybgruness',
        client_secret='fd68c095-0300-11ee-9341-0a1628958560',
        post_logout_redirect_uris=[mode.server + 'site_x/logout']) # your post logout uri (optional)

provider_config_18 = ProviderConfiguration(issuer= 'https://preprod.jeprouvemonage.fr/api/v1.0',
                                        client_metadata=client_metadata_18)


# +18 Talao
client_metadata_18_talao = ClientMetadata(
        client_id='dybgruness',
        client_secret='fd68c095-0300-11ee-9341-0a1628958560',
        post_logout_redirect_uris=[mode.server + 'site_x/logout']) # your post logout uri (optional)

provider_config_18_talao = ProviderConfiguration(issuer= 'https://jeprouvemonage.talao.co/api/v1.0',
                                        client_metadata=client_metadata_18_talao)



# 15
client_metadata_15 = ClientMetadata(
        client_id='ddoyrkbtrg',
        client_secret='b3404d62-1720-11ee-a6b4-0a1628958560',
        post_logout_redirect_uris=[mode.server + 'site_x/logout']) # your post logout uri (optional)

provider_config_15 = ProviderConfiguration(issuer= 'https://preprod.jeprouvemonage.fr/api/v1.0',
                                        client_metadata=client_metadata_15)




auth = OIDCAuthentication({'provider_18': provider_config_18, 'provider_18_talao': provider_config_18_talao,'provider_15': provider_config_15}, app)
#auth = OIDCAuthentication({'provider_18': provider_config_18, 'provider_15': provider_config_15}, app)


""" 
Verifiable Credential presented by user is transfered through vp_token in OAuth2 userinfo endpoint

"""
@app.route('/pornhub',  methods = ['GET', 'POST'])
def site_x():
	if request.method == "GET" :
		session.clear()
		return render_template('site_x.html')
	else :
		return redirect('/pornhub/login') 




@app.route('/pornhub15',  methods = ['GET', 'POST'])
def site_x_15():
	if request.method == "GET" :
		session.clear()
		return render_template('site_x_15.html')
	else :
		return redirect('/pornhub15/login') 



@app.route('/pornhub/login')
@auth.oidc_auth('provider_18')
def index():
    user_session = UserSession(session)    
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo) # this is the user credential



@app.route('/pornhub15/login')
@auth.oidc_auth('provider_15')
def index_15():
    user_session = UserSession(session)    
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo) # this is the user credential

# jeprouvemonage.talao.co


@app.route('/pornhub_talao',  methods = ['GET', 'POST'])
def site_x_talao():
	if request.method == "GET" :
		session.clear()
		return render_template('site_x_talao.html')
	else :
		return redirect('/pornhub_talao/login') 
	
@app.route('/pornhub_talao/login')
@auth.oidc_auth('provider_18_talao')
def index_talao():
    user_session = UserSession(session)    
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo) # this is the user credential



# MAIN entry point. Flask test server
if __name__ == '__main__':
    app.run(host = mode.IP, port= mode.port, debug=True)