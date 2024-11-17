from flask import Flask, render_template, request
from config import BaseConfig
from database.database import DatabaseManager
from database.db_model import *
from datetime import datetime

from util.decorators import *

app = Flask(__name__)

app.config.from_object(BaseConfig)
with app.app_context():
    db.init_app(app)
    db.drop_all()
    db.create_all()


@app.route('/')
def index():
    """
    服务器状态页（WIP）
    :return: 渲染后的状态页
    """
    return render_template('index.html')


@app.route('/api/v1/register_app', methods=['POST'])
@auto_handle_exception_and_jsonify
def register_app():
    request_data = request.get_json()
    app_id, app_key = DatabaseManager.register_app(request_data.get('description'))
    return {'status': 0, 'app_id': app_id, 'app_key': app_key}


@app.route('/api/v1/register_user', methods=['POST'])
@auto_handle_exception_and_jsonify
def register_user():
    request_data = request.get_json()
    app_id = request_data.get('app_id', '')
    sign = request_data.get('sign', '')
    username = request_data.get('username', '')
    password = request_data.get('password', '')
    description = request_data.get('description', '')
    salt = request_data.get('salt', '')

    DatabaseManager.verify_app(app_id, sign, username, password, description, salt)
    user = DatabaseManager.register_user(username, password, description)
    return {
        'status': 0,
        'username': user.username,
        'role': user.role
    }


@app.route('/api/v1/login_user', methods=['POST'])
@auto_handle_exception_and_jsonify
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
    request_data = request.get_json()
    app_id = request_data.get('app_id', '')
    sign = request_data.get('sign', '')
    username = request_data.get('username', '')
    password = request_data.get('password', '')
    salt = request_data.get('salt', '')

    DatabaseManager.verify_app(app_id, sign, username, password, salt)

    user_session = DatabaseManager.login_user(username, password)
    return {
        'status': 0,
        'session': user_session.user_session,
        'exp_time': user_session.exp_time.timestamp()
    }


@app.route('/api/v1/change_user_password', methods=['POST'])
@auto_handle_exception_and_jsonify
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

    return {
        'status': 0,
        'username': username,
    }


@app.route('/api/v1/get_user_info', methods=['POST'])
@auto_handle_exception_and_jsonify
def get_user_info():
    request_data = request.get_json()
    app_id = request_data.get('app_id', '')
    sign = request_data.get('sign', '')
    session = request_data.get('session', '')
    username = request_data.get('username', '')
    salt = request_data.get('salt', '')
    DatabaseManager.verify_app(app_id, sign, session, username, salt)
    DatabaseManager.get_user_by_session(session)
    user = DatabaseManager.get_user_info(username)
    return {
        'status': 0,
        'username': user.username,
        'role': user.role,
        'description': user.description,
        'reg_time': user.reg_time.timestamp(),
        'last_use_time': user.last_use_time.timestamp()
    }


@app.route('/api/v1/heartbeat', methods=['POST'])
@auto_handle_exception_and_jsonify
def heartbeat():
    request_data = request.get_json()
    app_id = request_data.get('app_id', '')
    sign = request_data.get('sign', '')
    session = request_data.get('session', '')
    salt = request_data.get('salt', '')
    DatabaseManager.verify_app(app_id, sign, session, salt)
    user = DatabaseManager.get_user_by_session(session)

    return {
        'status': 0,
        'username': user.username,
        'current_time': datetime.now().timestamp()
    }


@app.route('/api/v1/send_direct_message', methods=['POST'])
@auto_handle_exception_and_jsonify
def send_direct_message():
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

    return {
        'status': 0,
        'send_user': send_user.username,
        'recv_user': recv_user.username,
        'send_time': datetime.now().timestamp()
    }


@app.route('/api/v1/get_direct_message', methods=['POST'])
@auto_handle_exception_and_jsonify
def get_direct_message():
    request_data = request.get_json()
    app_id = request_data.get('app_id', '')
    sign = request_data.get('sign', '')
    session = request_data.get('session', '')
    salt = request_data.get('salt', '')

    DatabaseManager.verify_app(app_id, sign, session, salt)
    recv_user = DatabaseManager.get_user_by_session(session)
    return DatabaseManager.get_direct_message(recv_user)


@app.route('/api/v1/get_direct_message/all_cache', methods=['POST'])
@auto_handle_exception_and_jsonify
def get_direct_message_all_cache():
    request_data = request.get_json()
    app_id = request_data.get('app_id', '')
    sign = request_data.get('sign', '')
    session = request_data.get('session', '')
    salt = request_data.get('salt', '')

    DatabaseManager.verify_app(app_id, sign, session, salt)
    recv_user = DatabaseManager.get_user_by_session(session)
    return DatabaseManager.get_direct_message(recv_user, skip_delivered=False)


@app.route('/api/v1/register_group', methods=['POST'])
@auto_handle_exception_and_jsonify
def register_group():
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
    return {
        'status': 0,
        'gid': group.id,
        'register_time': datetime.now().timestamp()
    }


@app.route('/api/v1/send_group_message', methods=['POST'])
@auto_handle_exception_and_jsonify
def send_group_message():
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

    return {
        'status': 0,
        'send_user': send_user.username,
        'group': group.name,
        'send_time': datetime.now().timestamp()
    }


@app.route('/api/v1/get_group_message', methods=['POST'])
@auto_handle_exception_and_jsonify
def get_group_message():
    request_data = request.get_json()
    app_id = request_data.get('app_id', '')
    sign = request_data.get('sign', '')
    session = request_data.get('session', '')
    gid = request_data.get('gid', '')
    salt = request_data.get('salt', '')
    DatabaseManager.verify_app(app_id, sign, session, gid, salt)

    recv_user = DatabaseManager.get_user_by_session(session)
    group = DatabaseManager.get_group_by_id(gid)
    return DatabaseManager.get_group_message(group)


@app.route('/api/v1/get_group_info', methods=['POST'])
@auto_handle_exception_and_jsonify
def get_group_info():
    request_data = request.get_json()
    app_id = request_data.get('app_id', '')
    sign = request_data.get('sign', '')
    session = request_data.get('session', '')
    gid = request_data.get('gid', '')
    salt = request_data.get('salt', '')
    DatabaseManager.verify_app(app_id, sign, session, gid, salt)

    group = DatabaseManager.get_group_by_id(gid)
    return {
        'status': 0,
        'gid': group.id,
        'name': group.name,
        'description': group.description,
        'reg_time': group.reg_time.timestamp(),
        'last_use_time': group.last_use_time.timestamp()
    }


@app.before_request
def clean_sessions():
    DatabaseManager.clean_sessions()


if __name__ == '__main__':
    app.run()
