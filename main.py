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
import json
import markdown.extensions.fenced_code
from components import message
from flask_session import Session
from flask_mobility import Mobility
from flask_simple_captcha import CAPTCHA


# local dependencies
from routes import web_emailpass, web_phonepass, yoti, dapp_register_gamer_pass
from routes import tezotopia, twitter, chainborn,  oidc4vci_kyc, polygonid, counter
from routes import verifier_defi_nft, verifier_defi_tezid
import environment

import logging
logging.basicConfig(level=logging.INFO)
ISSUER_CONFIG = {
    'SECRET_CAPTCHA_KEY': json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key']),  # use for JWT encoding/decoding
    'CAPTCHA_LENGTH': 6,  # Length of the generated CAPTCHA text
    'CAPTCHA_DIGITS': False,  # Should digits be added to the character pool?
    # EXPIRE_SECONDS will take prioritity over EXPIRE_MINUTES if both are set.
    'EXPIRE_SECONDS': 60 * 10,
    #'EXPIRE_MINUTES': 10, # backwards compatibility concerns supports this too
    #'EXCLUDE_VISUALLY_SIMILAR': True,  # Optional
    #'ONLY_UPPERCASE': True,  # Optional
    #'CHARACTER_POOL': 'AaBb',  # Optional
}
ISSUER_CAPTCHA = CAPTCHA(config=ISSUER_CONFIG)

LANGUAGES = ['en', 'fr']

# Redis est utilisé pour stocker les données de session
red = redis.Redis(host='localhost', port=6379, db=0)

logging.info("python version : %s", sys.version)
logging.info("didkit version = %s", didkit.get_version())

# init
myenv = os.getenv('MYENV')
if not myenv:
	myenv = 'local'
mode = environment.currentMode(myenv)
app = Flask(__name__)
qrcode = QRcode(app)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'altme_issuer'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60) # session lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "issuer" + mode.password
app.jinja_env.globals['Version'] = "2.0.1"

app = ISSUER_CAPTCHA.init_app(app)

# site X
app.config.update(
    OIDC_REDIRECT_URI=mode.server + 'callback', # your application redirect uri. Must not be used in your code
    SECRET_KEY="lkjhlkjh" # your application secret code for session, random
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
web_phonepass.init_app(ISSUER_CAPTCHA, app, red, mode)
dapp_register_gamer_pass.init_app(app, red, mode)
yoti.init_app(app, red, mode)
tezotopia.init_app(app, red, mode)
twitter.init_app(app, red, mode)
chainborn.init_app(app, red, mode)
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
	if not session.get('language'):
		session['language'] = request.accept_languages.best_match(LANGUAGES)
	else:
		refresh()
	return "en"

																													
@app.route('/language', methods=['GET'], defaults={'mode': mode})
def user_language(mode):
    #session['language'] = request.args['lang']
	session['language'] = "en"
	return 'en'


@app.route('/md_file', methods = ['GET', 'POST'])
def md_file():
	"""
	https://dev.to/mrprofessor/rendering-markdown-from-flask-1l41
	"""
	if request.args['file'] == 'privacy' :
		try:
			content = open('privacy_'+ session['language'] + '.md', 'r').read()
		except Exception:
			content = open('privacy_en.md', 'r').read()
	
	elif request.args['file'] == 'terms_and_conditions' :
		try:
			content = open('cgu_'+ session['language'] + '.md', 'r').read()
		except Exception:
			content = open('cgu_en.md', 'r').read()
	return render_template_string( markdown.markdown(content, extensions=["fenced_code"]))


@app.route('/company/', methods = ['GET', 'POST'])
def company():
	return render_template('company.html')


@app.route('/', methods=['GET']) 
def test():
	return jsonify("Hello")


# MAIN entry point. Flask test server
if __name__ == '__main__':
    app.run(host=mode.IP, port= mode.port, debug=True)