"""
Python 3.9 ++
didkit 0.3.0 get_version
"""
from flask import Flask, jsonify, session, request, render_template_string, render_template
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


# local dependencies
from routes import web_emailpass, web_phonepass, web_passbase, web_talao_community, vc_issuer, yoti, dapp_register_gamer_pass
from routes import tezotopia, twitter, chainborn, bloometa, oidc4vci_kyc
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
app.jinja_env.globals['Version'] = "4.6"

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
web_talao_community.init_app(app, red, mode)
web_passbase.init_app(app, red, mode)
dapp_register_gamer_pass.init_app(app, red, mode)
yoti.init_app(app, red, mode)
tezotopia.init_app(app, red, mode)
twitter.init_app(app, red, mode)
chainborn.init_app(app, red, mode)
bloometa.init_app(app, red, mode)
oidc4vci_kyc.init_app(app, red, mode)


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


# MAIN entry point. Flask test server
if __name__ == '__main__':
    app.run(host = mode.IP, port= mode.port, debug=True)