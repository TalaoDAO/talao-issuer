
workers = 5
worker_class = 'gevent' 

loglevel = 'info'
errorlog = "-"
accesslog = "-"

timeout = 30  # sec
keepalive = 504  # sec
capture_output = True

# Environment variables
raw_env = ["MYENV=aws"]
