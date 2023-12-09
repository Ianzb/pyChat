import random
import urllib.request
import json
import hashlib

url = 'http://127.0.0.1:5000/api/v1/register_user'

app_id = 'MZFiLAzmJu'
app_key = 'vUCiKf167oNUfpdbsxKs'
username = 'test4'
password = 'test_password4'
description= 'Test test test...'
salt = str(random.randint(1, 100000))
sign_str = app_id + app_key + username + password + description + salt
sign = hashlib.sha256(sign_str.encode()).hexdigest()

data = {
    'app_id': app_id,
    'username': username,
    'password': password,
    'description': description,
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
