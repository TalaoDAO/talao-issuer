""" for token see passwords.json 
https://ssl.smsapi.com/#/payments/transfer/success
"""

from smsapi.client import SmsApiComClient
from smsapi.exception import SmsApiException
from flask_babel import _

import logging
logging.basicConfig(level=logging.INFO)

def send_code(phone, code, mode) :
	""" code = str, phone number with country code 33607182594 """
	token = mode.sms_token
	try :
		client = SmsApiComClient(access_token=token)
		send_results = client.sms.send(to=phone, message=_("# Your verification code is : ") + code)
		for result in send_results :
			logging.info('result =  %s %s %s', result.id, result.points, result.error)
			return True
	except SmsApiException as e:
		logging.error('%s',e.message)
		return False

def check_phone(phone, mode) :
	token = mode.sms_token
	try:
		client = SmsApiComClient(access_token=token)
		client.sms.send(to=phone, message=_("Your phone number has been verified."))
		return True
	except SmsApiException as e:
		logging.error('sms api message = %s', e.message)
		return False

