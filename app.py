import string
import threading

from flask import Flask, render_template, request, jsonify
from config import BaseConfig
from db_model import *
import hashlib
from datetime import datetime, timedelta
import localization as loc
import secrets

app = Flask(__name__)

app.config.from_object(BaseConfig)
with app.app_context():
    db.init_app(app)
    # db.drop_all()
    db.create_all()


def gen_str(length):
    letters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(letters) for _ in range(length))


class DatabaseManager:
    @staticmethod
    def verify_app(app_id, sign, *args):
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
        if q.count() == 0:
            raise APIError(608)
        elif q.first().exp_time < datetime.now():
            db.session.delete(q.first())
            db.session.commit()
            raise APIError(608)
        q.first().exp_time = datetime.now() + timedelta(minutes=5)
        db.session.commit()
        return DatabaseManager.get_user_info(q.first().username)

    @staticmethod
    def clean_sessions():
        q = db.session.query(UserSession)
        for i in q:
            if i.exp_time < datetime.now():
                db.session.delete(i)
        db.session.commit()

    @staticmethod
    def send_direct_message(send_user, recv_user, message):
        message_obj = Message(
            send_user=send_user.username,
            recv_user=recv_user.username,
            message=message,
            send_time=datetime.now()
        )
        DatabaseManager._add_new_line(message_obj)

    @staticmethod
    def get_direct_message(recv_user):
        messages = Message.query.filter_by(recv_user=recv_user.username)
        res = {
            'status': 0,
            'count': messages.count(),
            'messages': []
        }
        for m in messages:
            res['messages'].append({
                'username': m.send_user,
                'send_time': m.send_time,
                'message': m.message
            })
            db.session.delete(m)
        return res

    @staticmethod
    def register_group(group_name, description=""):
        reg_time = datetime.now()  # timestamp
        last_use_time = datetime.now()  # timestamp
        group = Group(
            name=group_name,
            description=description,
            reg_time=reg_time,
            last_use_time=last_use_time)
        db.session.add(group)
        db.session.commit()
        return group

    @staticmethod
    def get_group_by_id(gid):
        q = Group.query.filter_by(id=int(gid))
        if q.count() == 0:
            raise APIError(611)
        q.first().last_use_time = datetime.now()
        db.session.commit()
        return q.first()

    @staticmethod
    def send_group_message(send_user, group, message):
        message_obj = GroupMessage(
            send_user=send_user.username,
            gid=group.id,
            message=message,
            send_time=datetime.now()
        )
        DatabaseManager._add_new_line(message_obj)

    @staticmethod
    def get_group_message(group):
        messages = GroupMessage.query.filter_by(gid=group.id)
        res = {
            'status': 0,
            'count': messages.count(),
            'messages': []
        }
        for m in messages:
            res['messages'].append({
                'username': m.send_user,
                'send_time': m.send_time,
                'message': m.message
            })
        return res

    @staticmethod
    def register_app(description=""):
        """
        申请app_id和app_key
        :param description: app描述，50字符以内
        :return: app_id与app_key
        """
        while True:
            app_id = gen_str(10)
            if Application.query.filter_by(app_id=app_id).count() == 0:
                break
        app_key = gen_str(20)
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
        return user

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

            session = gen_str(20)
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
    def change_user_password(user, password):
        if DatabaseManager.check_user_password(user, password):
            raise APIError(609)
        user.password_hash = DatabaseManager._get_password_hash(password)
        db.session.commit()

    @staticmethod
    def change_user_role(user, role):
        if role != 0 or 1 or 2:
            raise APIError(610)
        user.role = role
        db.session.commit()

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
        user = DatabaseManager.register_user(username, password, description)
        response_data = {
            'status': 0,
            'username': user.username,
            'role': user.role
        }
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

        user_session = DatabaseManager.login_user(username, password)
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
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        username = request_data.get('username', '')
        new_password = request_data.get('new_password', '')
        salt = request_data.get('salt', '')

        DatabaseManager.verify_app(app_id, sign, session, username, new_password, salt)
        current_user = DatabaseManager.get_user_by_session(session)
        target_user = DatabaseManager.get_user_info(username)
        if (current_user.id == target_user.id
                or current_user.role == 2
                or (current_user.role == 1 and target_user.role == 0)):
            DatabaseManager.change_user_password(target_user, new_password)
        else:
            raise APIError(607)

        response_data = {
            'status': 0,
            'username': username,
        }
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/get_user_info', methods=['POST'])
def get_user_info():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        username = request_data.get('username', '')
        salt = request_data.get('salt', '')
        DatabaseManager.verify_app(app_id, sign, session, username, salt)
        DatabaseManager.get_user_by_session(session)
        user = DatabaseManager.get_user_info(username)
        response_data = {
            'status': 0,
            'username': user.username,
            'role': user.role,
            'description': user.description,
            'reg_time': user.reg_time,
            'last_use_time': user.last_use_time
        }
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)

@app.route('/api/v1/heartbeat', methods=['POST'])
def heartbeat():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        salt = request_data.get('salt', '')
        DatabaseManager.verify_app(app_id, sign, session, salt)
        user = DatabaseManager.get_user_by_session(session)

        response_data = {
            'status': 0,
            'username': user.username,
            'current_time': datetime.now()
        }
        return jsonify(response_data)
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/send_direct_message', methods=['POST'])
def send_direct_message():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        recv_username = request_data.get('recv_user', '')
        message = request_data.get('message', '')
        salt = request_data.get('salt', '')
        DatabaseManager.verify_app(app_id, sign, session, recv_username, message, salt)
        send_user = DatabaseManager.get_user_by_session(session)
        recv_user = DatabaseManager.get_user_info(recv_username)

        DatabaseManager.send_direct_message(send_user, recv_user, message)

        response_data = {
            'status': 0,
            'send_user': send_user.username,
            'recv_user': recv_user.username,
            'send_time': datetime.now()
        }
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/get_direct_message', methods=['POST'])
def get_direct_message():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        salt = request_data.get('salt', '')
        DatabaseManager.verify_app(app_id, sign, session, salt)
        recv_user = DatabaseManager.get_user_by_session(session)
        response_data = DatabaseManager.get_direct_message(recv_user)
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/register_group', methods=['POST'])
def register_group():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        group_name = request_data.get('group_name', '')
        description = request_data.get('description', '')
        salt = request_data.get('salt', '')
        DatabaseManager.verify_app(app_id, sign, session, group_name, description, salt)
        DatabaseManager.get_user_by_session(session)
        group = DatabaseManager.register_group(group_name, description)
        response_data = {
            'status': 0,
            'gid': group.id,
            'register_time': datetime.now()
        }
    except Exception as e:
        print(e)
    finally:
        return jsonify(response_data)


@app.route('/api/v1/send_group_message', methods=['POST'])
def send_group_message():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        gid = request_data.get('gid', '')
        message = request_data.get('message', '')
        salt = request_data.get('salt', '')
        DatabaseManager.verify_app(app_id, sign, session, gid, message, salt)
        send_user = DatabaseManager.get_user_by_session(session)
        group = DatabaseManager.get_group_by_id(gid)

        DatabaseManager.send_group_message(send_user, group, message)

        response_data = {
            'status': 0,
            'send_user': send_user.username,
            'group': group.name,
            'send_time': datetime.now()
        }
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/get_group_message', methods=['POST'])
def get_group_message():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        gid = request_data.get('gid', '')
        salt = request_data.get('salt', '')
        DatabaseManager.verify_app(app_id, sign, session, gid, salt)

        recv_user = DatabaseManager.get_user_by_session(session)
        group = DatabaseManager.get_group_by_id(gid)
        response_data = DatabaseManager.get_group_message(group)
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.route('/api/v1/get_group_info', methods=['POST'])
def get_group_info():
    response_data = APIError.default_response_data()
    try:
        request_data = request.get_json()
        app_id = request_data.get('app_id', '')
        sign = request_data.get('sign', '')
        session = request_data.get('session', '')
        gid = request_data.get('gid', '')
        salt = request_data.get('salt', '')
        DatabaseManager.verify_app(app_id, sign, session, gid, salt)

        group = DatabaseManager.get_group_by_id(gid)
        response_data = {
            'status': 0,
            'gid': group.id,
            'name': group.name,
            'description': group.description,
            'reg_time': group.reg_time,
            'last_use_time': group.last_use_time
        }
    except APIError as e:
        response_data = e.gen_response_data()
    finally:
        return jsonify(response_data)


@app.before_request
def clean_sessions():
    DatabaseManager.clean_sessions()


if __name__ == '__main__':
    app.run()
