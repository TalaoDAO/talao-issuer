import os

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:5100")
workers = int(os.getenv("GUNICORN_WORKERS", "2"))
worker_class = "gthread"
threads = int(os.getenv("GUNICORN_THREADS", "4"))

loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")
errorlog = "-"
accesslog = "-"
capture_output = True

timeout = 60
keepalive = 5
raw_env = ["MYENV=aws"]
