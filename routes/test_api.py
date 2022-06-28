# https://appdividend.com/2022/03/20/python-requests-post/

import requests
import json

url = "https://talao.co/analytics/api/newvoucher"
url = "http://192.168.0.65:8000"
headers = {
    "key" : "SECRET_KEY",
    "Content-Type": "application/x-www-form-urlencoded",
    }
data = {"voucher" : {"test" : "essai"}}
r = requests.post(url, data=json.dumps(data), headers=headers)
print(r.text)
if not 199<r.status_code<300 :
    print("API call rejected %s", r.status_code)
else :
    print("API call accepted %s", r.status_code)
    