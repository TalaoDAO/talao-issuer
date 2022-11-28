# local call --> gunicorn -c gunicornconf.py  --reload wsgi:app

#import multiprocessing

# to be removed for Nginx on AWS 
#bind = '127.0.0.1:3000'


workers = 5
worker_class = 'gevent' 

loglevel = 'info'
#errorlog = os.path.join(_VAR, 'log/api-error.log')
#accesslog = os.path.join(_VAR, 'log/api-access.log')
errorlog = "-"
accesslog = "-"



timeout = 30  # sec
keepalive = 504  # sec
#timeout = 3 * 60  # 3 minutes
#keepalive = 5 * 24 * 60 * 60  # 5 days
capture_output = True

# Environment variables
raw_env = ["MYENV=aws"]
