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
from flask_babel import Babel, _, refresh
from datetime import timedelta
import markdown
import markdown.extensions.fenced_code

from flask_session import Session
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession



# local dependencies
from routes import web_emailpass, web_phonepass, web_passbase, vc_issuer, yoti, dapp_register_gamer_pass
from routes import tezotopia, twitter, chainborn, bloometa, oidc4vci_kyc, polygonid, counter
from routes import verifier_defi_nft
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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=360) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "issuer" + mode.password
app.jinja_env.globals['Version'] = "4.8"

# site X
app.config.update(
    OIDC_REDIRECT_URI = mode.server + 'callback', # your application redirect uri. Must not be used in your code
    SECRET_KEY = "lkjhlkjh" # your application secret code for session, random
)
babel = Babel(app)

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
vc_issuer.init_app(app, red, mode)
web_passbase.init_app(app, red, mode)
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


### SITE X

client_metadata = ClientMetadata(
        client_id='cxltfjraph',
        client_secret= "d5aa3daa-dacd-11ed-b76d-0a1628958560",
        post_logout_redirect_uris=[mode.server + 'site_x/logout']) # your post logout uri (optional)

provider_config = ProviderConfiguration(issuer= 'https://talao.co/sandbox/op',
                                        client_metadata=client_metadata)
auth = OIDCAuthentication({'default': provider_config}, app)


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
   

@app.route('/pornhub/login')
@auth.oidc_auth('default')
def index():
    user_session = UserSession(session)    
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo) # this is the user credential


# MAIN entry point. Flask test server
if __name__ == '__main__':
    app.run(host = mode.IP, port= mode.port, debug=True)