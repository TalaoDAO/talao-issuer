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
		self.deeplink = 'https://app.talao.co/'		
		with open("./passwords.json", "r") as read_content: 
			passwords = json.load(read_content)
		self.analytics_key = passwords['analytics']
		self.password = passwords['password']
		self.passbase = passwords['passbase']
		self.smtp_password = passwords['smtp_password'] # used in smtp.py
		self.sms_token = passwords['sms_token'] # used in sms.py		
		self.deeplink = 'https://app.talao.co/'		
	
		# En Prod chez AWS 
		if self.myenv == 'aws':
			self.sys_path = '/home/admin'
			self.server = 'https://issuer.talao.co/'
			self.IP = '3.130.207.31' 
		elif self.myenv == 'local' :
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
