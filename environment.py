import socket
import json
import logging
import sys

logging.basicConfig(level=logging.INFO)

class currentMode() :
	def __init__(self, myenv):
		self.admin = 'thierry.thevenet@talao.io'
		self.test = True
		self.myenv = myenv
		self.deeplink_talao = 'https://app.talao.co/'	
		self.deeplink_altme = 'https://app.altme.io/'			
		with open("./passwords.json", "r") as read_content: 
			passwords = json.load(read_content)
		self.yoti = passwords['yoti']                                # yoti.py
		self.analytics_key = passwords['analytics']
		self.analytics_key2 = passwords['analytics2']
		self.pinata_api_key = passwords['pinata_api_key'] # used in Talao_ipfs.py
		self.pinata_secret_api_key = passwords['pinata_secret_api_key'] # used in Talao_ipfs.py
		self.password = passwords['password']
		self.altme_passbase_check = passwords['altme_passbase_check'] # web_passabse.py
		self.altme_wallet_webhook = passwords['altme_wallet_webhook'] # web_passbase.py
		self.altme_ai_token = passwords['altme_ai_token'] 			  # yoti.py
		self.tezid_issuer_key = passwords['tezid-issuer-key']
		self.tezotopia_issuer_key = passwords['tezotopia-issuer-key']
		self.altme_wallet_token = passwords['altme_wallet_token']     # vc_issuer.py
		self.passbase = passwords['passbase'] # web_passebase.py
		self.chainborn_api_key = passwords['chainborn_api_key']       # chainborn.py                 
		self.smtp_password = passwords['smtp_password'] 			  # smtp.py
		self.sms_token = passwords['sms_token']                       # sms.py		
	
		# En Prod chez AWS 
		if self.myenv == 'aws':
			self.yoti_pem_file = '/home/admin/issuer/key.pem'
			self.sys_path = '/home/admin'
			self.server = 'https://issuer.talao.co/'
			self.IP = '3.130.207.31' 
		elif self.myenv == 'local' :
			self.yoti_pem_file = '/home/thierry/issuer/key.pem'
			self.sys_path = '/home/thierry'
			self.server = 'http://' + extract_ip() + ':5000/'
			self.IP = extract_ip()
			self.port = 5000
		else :
			logging.error('environment variable problem')
			sys.exit()
		self.help_path = self.sys_path + '/issuer/templates/'


def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP
