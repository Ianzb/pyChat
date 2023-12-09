import random
import urllib.request
import json
import hashlib

url = 'http://127.0.0.1:5000/api/v1/send_direct_message'

app_id = 'MZFiLAzmJu'
app_key = 'vUCiKf167oNUfpdbsxKs'
session = '2iIUlqdSHp1QmsFN77pU'
recv_user = 'test3'
message = '''
Hello, Ianzb!
'''
salt = str(random.randint(1, 100000))
sign_str = app_id + app_key + session + recv_user + message + salt
sign = hashlib.sha256(sign_str.encode()).hexdigest()

data = {
    'app_id': app_id,
    'session': session,
    'recv_user': recv_user,
    'message': message,
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
