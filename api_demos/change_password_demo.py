import random
import urllib.request
import json
import hashlib

from constants import BASE_URL

url = BASE_URL + '/api/v1/change_user_password'

app_id = 'MZFiLAzmJu'
app_key = 'vUCiKf167oNUfpdbsxKs'
session = 'KlRprdDv1a6E2ib2n61X'
username = 'test'
new_password = 'ohhhhhh'
salt = str(random.randint(1, 100000))
sign_str = app_id + app_key + session + username + new_password + salt
sign = hashlib.sha256(sign_str.encode()).hexdigest()

data = {
    'app_id': app_id,
    'session': session,
    'username': username,
    'new_password': new_password,
    'salt': salt,
    'sign': sign
}
print(data)
headers = {'Content-Type': 'application/json'}
json_data = json.dumps(data).encode('utf8')

req = urllib.request.Request(url=url, data=json_data, headers=headers)
response = urllib.request.urlopen(req)
result = response.read().decode('utf8')
print(result)
