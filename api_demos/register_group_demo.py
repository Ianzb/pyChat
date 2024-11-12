import random
import urllib.request
import json
import hashlib

from api_demos.constants import BASE_URL

url = BASE_URL + '/api/v1/register_group'

app_id = 'MZFiLAzmJu'
app_key = 'vUCiKf167oNUfpdbsxKs'
session = '2iIUlqdSHp1QmsFN77pU'
group_name = 'A Random Group'
description = 'This is a random group.'
salt = str(random.randint(1, 100000))
sign_str = app_id + app_key + session + group_name + description + salt
sign = hashlib.sha256(sign_str.encode()).hexdigest()

data = {
    'app_id': app_id,
    'session': session,
    'group_name': group_name,
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
