# Installation

## Requirements

Python 3.9+
didkit 0.3.0

## Install

mkdir issuer  
cd issuer
python3.10 -m venv venv  
. venv/bin/activate  

pip install redis  
pip install Flask-Session  
pip install Flask[async]  
pip install didkit==0.3.0  
pip install Flask-QRcode  
pip install jwcrypto  
pip install pyjwt  
pip install gunicorn  
pip install Flask-Babel
pip install Markdown
pip install smsapi
pip install requests
pip install smsapi-client

git init
git pull https://github.com/TalaoDAO/talao-issuer.git 

## Run

python main.py
