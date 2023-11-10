from flask import Flask, render_template, request, jsonify
from config import BaseConfig
from strgen import StringGenerator
from db_model import *
import hashlib
from datetime import datetime, timedelta
import localization as loc

app = Flask(__name__)

app.config.from_object(BaseConfig)
with app.app_context():
    db.init_app(app)
    # db.drop_all()
    db.create_all()


class DatabaseManager:
    @staticmethod
    def verify_app(app_id, sign, *args):.
        """
        app鉴权
        :param app_id: 调用api的app_id
        :param sign: 签名，使用字符串拼接+sha256计算。字符串：app_id + app_key + args
        :param args: api参数，客户端需与服务器顺序一致
        :return: 0 成功鉴权
        """
        q = Application.query.filter_by(app_id=app_id)
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
                db.session.commit()
                return 0
            else:
                raise APIError(602)

    @staticmethod
    def _get_password_hash(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def get_user_by_session(session):
        q = UserSession.query.filter_by(user_session=session)
        if q.count() == 0 or q.first().exp_time < datetime.now():
            raise APIError(607)

        # TODO

    @staticmethod
    def register_app(description=""):
        """
        申请app_id和app_key
        :param description: app描述，50字符以内
        :return: app_id与app_key
        """
        while True:
            app_id = StringGenerator("[\\l\\d]{10}").render()
            if Application.query.filter_by(app_id=app_id).count() == 0:
                break
        app_key = StringGenerator("[\\l\\d]{20}").render()
        reg_time = datetime.now()  # timestamp
        last_use_time = datetime.now()  # timestamp
        application = Application(
            app_id=app_id,
            app_key=app_key,
            description=description,
            available=1,
            reg_time=reg_time,
            last_use_time=last_use_time)
        db.session.add(application)
        db.session.commit()
        return app_id, app_key

    @staticmethod
    def register_user(username, password, description="", role=0):
        """
        用指定的用户名和密码注册用户
        :param username: 要注册的用户名
        :param password: 设置的密码，实际在数据库中以sha-256存储
        :param description: 备注，可以为空
        :return: User对象
        """

        if username == '' or password == '' or len(username) > 20:
            raise APIError(604)
        password_hash = DatabaseManager._get_password_hash(password)
        reg_time = datetime.now()
        last_use_time = datetime.now()
        user = User(
            username=username,
            role=role,
            password_hash=password_hash,
            description=description,
            reg_time=reg_time,
            last_use_time=last_use_time)
        DatabaseManager._add_new_line(user)
        return User

    @staticmethod
    def login_user(username, password, exp_time_delta=None):
        """
        登录指定用户
        :param username: 要登录的用户名
        :param password: 该用户名的密码
        :param exp_time_delta: 有效时长，timedelta对象
        :return: UserSession对象
        """
        if exp_time_delta is None:
            exp_time_delta = timedelta(minutes=5)
        user = DatabaseManager.get_user_info(username)
        if DatabaseManager.check_user_password(user, password):
            user.last_use_time = datetime.now()

            session = StringGenerator("[\\l\\d]{20}").render()
            exp_time = datetime.now() + exp_time_delta
            user_session = UserSession(
                user_session=session,
                exp_time=exp_time,
                username=user.username
            )
            db.session.add(user_session)
            db.session.commit()
            return user_session
        else:
            raise APIError(604)

    @staticmethod
    def get_user_info(username):
        """
        以用户名查找用户信息
        :param username: 要查找的用户名
        :return: User对象
        """
        if type(username) != str or username == '' or len(username) > 20:
            raise APIError(604)
        q = User.query.filter_by(username=username)
        if q.count() == 0:
            raise APIError(606)
        return q.first()

    @staticmethod
    def check_user_password(user, password):
        """
        检查用户密码是否一致
        :param user: User对象
        :return: true一致，false不一致
        """
        return user.password_hash == DatabaseManager._get_password_hash(password)


    @staticmethod
    def _add_new_line(obj):
        db.session.add(obj)
        db.session.commit()



class APIError(Exception):
    def __init__(self, err_no):
        self.err_no = err_no
        self.err_info = loc.err_info.get(err_no, loc.err_info[600])
        pass

    def gen_response_data(self):
        return {
            'status': -1,
            'err_no': self.err_no,
            'err_info': self.err_info
        }

    @classmethod
    def default_response_data(cls):
        return cls(600).gen_response_data()


@app.route('/')
def index():
    """
    服务器状态页（WIP）
    :return: 渲染后的状态页
    """
    return render_template('index.html')


@app.route('/api/v1/register_app', methods=['POST'])
def register_app():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id, app_key = DatabaseManager.register_app(request_data.get('description'))
        response_data = {'status': 0, 'app_id': app_id, 'app_key': app_key}
    except Exception as e:
        print(e)
    finally:
        return jsonify(response_data)


@app.route('/api/v1/register_user', methods=['POST'])
def register_user():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        username = request_data.get('username', '')
        password = request_data.get('password', '')
        description = request_data.get('description', '')
        salt = request_data.get('salt', '')

        DatabaseManager.verify_app(app_id, sign, username, password, description, salt)
        DatabaseManager.register_user(username, password, description)
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/login_user', methods=['POST'])
def login_user():
    """
    登录指定用户
    add_id: 执行操作的app_id
    sign: 签名，使用sha-256计算，拼接app_id+username+password+salt
    username: 要登录的用户名
    password: 该用户名的密码
    salt: 盐值，理论为任意字符串，实际操作可以为空
    :return: 成功执行，'status': 0, 'session': 登录session，默认5分钟后过期, 'exp_time': 过期时间
    """
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        username = request_data.get('username', '')
        password = request_data.get('password', '')
        salt = request_data.get('salt', '')

        DatabaseManager.verify_app(app_id, sign, username, password, salt)

        user_session = DatabaseManager.login_user()
        response_data = {
            'status': 0,
            'session': user_session.user_session,
            'exp_time': user_session.exp_time
        }
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/change_user_password', methods=['POST'])
def change_user_password():
    """
    更改指定用户的密码
    app_id: 执行操作的app_id
    sign: 签名，使用sha-256计算，拼接app_id+session+username+new_password+salt
    username: 要更改密码的用户
    new_password: 新密码
    salt: 盐值，理论为任意字符串，实际操作可以为空

    权限：
    0 普通用户只可以改变自己的密码
    1,2 admin和super admin可以改变任何人的密码
    :return:
    """
    response_data = APIError().gen_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        username = request_data.get('username', '')
        new_password = request_data.get('new_password', '')
        salt = request_data.get('salt', '')

        verify_app(app_id, sign, session, username, new_password, salt)

        q = User.query.filter_by(username=username)
        if q.count() == 0:
            raise APIError(606)


        if

        q.first().last_use_time = datetime.now()

        session = StringGenerator("[\\l\\d]{20}").render()
        exp_time = datetime.now() + timedelta(minutes=5)

        user_session = UserSession(
            user_session=session,
            exp_time=exp_time,
            user_id=q.first().id
        )
        db.session.add(user_session)

        db.session.commit()
        response_data = {
            'status': 0,
            'session': session,
            'exp_time': exp_time
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
