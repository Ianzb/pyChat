import hashlib
from datetime import datetime, timedelta

from util.util import gen_str
from util.exception import APIError
from database.db_model import Application, db, UserSession, Message, Group, GroupMessage, User


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
            send_time=datetime.now(),
            delivered=False
        )
        DatabaseManager._add_new_line(message_obj)

    @staticmethod
    def get_direct_message(recv_user, skip_delivered=True, auto_mark_delivered=True):
        messages = Message.query.filter_by(recv_user=recv_user.username)
        res = {
            'status': 0,
            'count': messages.count(),
            'messages': []
        }
        for m in messages:
            if skip_delivered and m.delivered:
                continue
            res['messages'].append({
                'username': m.send_user,
                'send_time': m.send_time,
                'message': m.message
            })
            if auto_mark_delivered:
                DatabaseManager._mark_direct_message_received(m)
            # db.session.delete(m)
        return res

    @staticmethod
    def _mark_direct_message_received(m):
        m.delivered = True
        db.session.commit()

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
