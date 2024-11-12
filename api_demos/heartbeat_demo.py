import random
import urllib.request
import json
import hashlib
import time

from api_demos.constants import BASE_URL

url = BASE_URL + '/api/v1/heartbeat'

while True:
    app_id = 'MZFiLAzmJu'
    app_key = 'vUCiKf167oNUfpdbsxKs'
    session = '2iIUlqdSHp1QmsFN77pU'
    salt = str(random.randint(1, 100000))
    sign_str = app_id + app_key + session + salt
    sign = hashlib.sha256(sign_str.encode()).hexdigest()

    data = {
        'app_id': app_id,
        'session': session,
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
    time.sleep(60)
