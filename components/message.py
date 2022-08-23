import smtplib
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from email.mime.text import MIMEText
import codecs
import logging
logging.basicConfig(level=logging.INFO)


signature = '\r\n\r\n\r\nThe Altme team.\r\nhttps://altme.io/'


# dict of HTML templates with commented formating needed
HTML_templates = {'code_auth_en' : 'templates/code_auth_en.html', # code
				'code_auth_fr' : 'templates/code_auth_fr.html', # code
} 

def messageHTML(subject, to, HTML_key, format_dict, mode)  :
	password = mode.smtp_password
	fromaddr = "relay@talao.io"
	toaddr = [to]

	msg = MIMEMultipart()
	msg['From'] = formataddr((str(Header('Altme', 'utf-8')), fromaddr))
	msg['To'] = ", ".join(toaddr)
	msg['Subject'] = subject
	# string to store the body of the mail

	if HTML_key not in HTML_templates:
		logging.error('wrong HTML_key')
		return False

	template = HTML_templates[HTML_key]
	try :
		html = str(codecs.open(template, 'r', 'utf-8').read()).format(**format_dict)
	except Exception as e:
		logging.error('Upload email template  : %s', str(e))
		return False

	msg.attach(MIMEText(html, 'html', 'utf-8'))
	#p = MIMEBase('application', 'octet-stream')

	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	s.starttls()
	s.login(fromaddr, password)
	text = msg.as_string()

	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
		logging.info('email sent')
		s.quit()
		return True
	except:
		logging.error('sending mail')
		s.quit()
		return False


def message(subject, to, messagetext, mode) :

	password = mode.smtp_password

	fromaddr = "relay@talao.io"
	toaddr = [to]

	msg = MIMEMultipart()
	msg['From'] = formataddr((str(Header('Altme', 'utf-8')), fromaddr))
	msg['To'] = ", ".join(toaddr)
	msg['Subject'] =  subject
	body = messagetext + signature
	msg.attach(MIMEText(body, 'plain'))
	#p = MIMEBase('application', 'octet-stream')

	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	s.starttls()
	s.login(fromaddr, password)
	text = msg.as_string()

	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
	except:
		logging.error('sending mail')
		return False
	s.quit()
	return True


