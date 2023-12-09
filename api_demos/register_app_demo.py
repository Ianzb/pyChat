import random
import urllib.request
import json
import hashlib

url = 'http://124.221.74.246:82/api/v1/register_app'

description= 'Test test test...'

data = {
    'description': description,
}
print(data)
headers = {'Content-Type': 'application/json'}
json_data = json.dumps(data).encode('utf8')

req = urllib.request.Request(url=url, data=json_data, headers=headers)
response = urllib.request.urlopen(req)
result = response.read().decode('utf8')
print(result)
