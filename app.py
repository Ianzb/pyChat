from flask import Flask, render_template, request, jsonify
from config import BaseConfig
from strgen import StringGenerator
import db_model
import hashlib
from datetime import datetime
import localization as loc

app = Flask(__name__)

app.config.from_object(BaseConfig)
with app.app_context():
    db_model.db.init_app(app)
    # db_model.db.drop_all()
    db_model.db.create_all()


def verify_app(app_id, sign, *args):
    """
    app鉴权
    :param app_id: 调用api的app_id
    :param sign: 签名，使用字符串拼接+sha256计算。字符串：app_id + app_key + args
    :param args: api参数，客户端需与服务器顺序一致
    :return: 0 成功鉴权
    """
    q = db_model.Application.query.filter_by(app_id=app_id)
    if q.count() == 0:
        raise APIError(601)
    elif q.first().available == 0:
        raise APIError(603)
    else:
        sign2_str = app_id + q.first().app_key
        for i in args:
            sign2_str += str(i)
        if sign == hashlib.sha256(sign2_str.encode()).hexdigest():
            q.first().last_use_time = datetime.now()
            db_model.db.session.commit()
            return 0
        else:
            raise APIError(602)


def get_password_hash(username, password):
    return hashlib.sha256((username + password).encode()).hexdigest()


class APIError(Exception):
    def __init__(self, err_no=600):
        self.err_no = err_no
        self.err_info = loc.err_info.get(err_no, loc.err_info[600])
        pass

    def gen_response_data(self):
        return {
            'status': -1,
            'err_no': self.err_no,
            'err_info': self.err_info
        }


@app.route('/')
def index():
    """
    服务器状态页（WIP）
    :return: 渲染后的状态页
    """
    return render_template('index.html')


@app.route('/api/v1/register_app', methods=['POST'])
def register_app():
    """
    申请app_id和app_key
    [description]: app描述，50字符以内
    :return: json，status=0为成功执行，同时返回app_id与app_key，status=-1为执行失败，同时返回err信息
    """
    response_data = APIError().gen_response_data()
    try:
        request_data = request.get_json()

        while True:
            app_id = StringGenerator("[\\l\\d]{10}").render()
            if db_model.Application.query.filter_by(app_id=app_id).count() == 0:
                break
        app_key = StringGenerator("[\\l\\d]{20}").render()
        description = request_data.get('description')
        reg_time = datetime.now()  # timestamp
        last_use_time = datetime.now()  # timestamp
        application = db_model.Application(
            app_id=app_id,
            app_key=app_key,
            description=description,
            available=1,
            reg_time=reg_time,
            last_use_time=last_use_time)
        db_model.db.session.add(application)
        db_model.db.session.commit()
        response_data = {'status': 0, 'app_id': app_id, 'app_key': app_key}
    except Exception as e:
        print(e)
    finally:
        return jsonify(response_data)


@app.route('/api/v1/register_user', methods=['POST'])
def register_user():
    response_data = APIError().gen_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        username = request_data.get('username', '')
        password = request_data.get('password', '')
        description = request_data.get('description', '')
        salt = request_data.get('salt', '')

        if username == '' or password == '' or len(username) > 20:
            raise APIError(604)

        verify_app(app_id, sign, username, password, description, salt)

        password_hash = get_password_hash(username, password)
        # print(password_hash)
        reg_time = datetime.now()  # timestamp
        last_use_time = datetime.now()  # timestamp
        user = db_model.User(
            username=username,
            role=0,
            password_hash=password_hash,
            description=description,
            reg_time=reg_time,
            last_use_time=last_use_time)
        db_model.db.session.add(user)
        db_model.db.session.commit()
        response_data = {
            'status': 0,
            'username': username,
            'role': 0,
            'password_hash': password_hash
        }
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/login_user', methods=['POST'])
def login_user():
    response_data = APIError().gen_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        username = request_data.get('username', '')
        password_hash = request_data.get('password_hash', '')
        salt = request_data.get('salt', '')

        if username == '' or password_hash == '' or len(username) > 20:
            raise APIError(604)

        verify_app(app_id, sign, username, password, salt)

        if db_model.User.query.filter_by(username=username).count() != 0:
            raise ValueError(605)

        password_hash = get_password_hash(username, password)
        print(password_hash)  # timestamp
        last_use_time = datetime.now()  # timestamp

        db_model.db.session.commit()
        response_data = {
            'status': 0,
            'username': username,
            'role': 0,
            'password_hash': password_hash
        }
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/heartbeat', methods=['POST'])
def heartbeat():
    request_data = request.get_json()
    timestamp = request_data.get('timestamp')
    app_id = request_data.get('app_id')
    token = request_data.get('token')
    response_data = {'timestamp': datetime.now(), 'status': 0}
    return jsonify(response_data)


if __name__ == '__main__':
    app.run()
