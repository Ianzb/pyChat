from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Application(db.Model):
    __tablename__ = "application"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.String(10), unique=True)
    app_key = db.Column(db.String(20))
    description = db.Column(db.String(50))
    available = db.Column(db.Integer) # 1-available 0-unavailable
    reg_time = db.Column(db.DateTime)
    last_use_time = db.Column(db.DateTime)


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    role = db.Column(db.Integer)  # 0-user, 1-admin, 2-super admin, 3-permanently banned
    password_hash = db.Column(db.String(64))  # hashed by sha256, salt: username
    description = db.Column(db.String(50))
    reg_time = db.Column(db.DateTime)
    last_use_time = db.Column(db.DateTime)


class UserSession(db.Model):
    __tablename__ = "user_session"
    id = db.Column(db.Integer, primary_key=True)
    user_session = db.Column(db.String(20), unique=True)
    exp_time = db.Column(db.DateTime)
    username = db.Column(db.ForeignKey('user.username'))


class Group(db.Model):
    __tablename__ = "group"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True)
    description = db.Column(db.String(50))
    reg_time = db.Column(db.DateTime)
    last_use_time = db.Column(db.DateTime)

class Message(db.Model):
    __tablename__ = "message"
    id = db.Column(db.Integer, primary_key=True)
    send_user = db.Column(db.ForeignKey('user.username'))
    recv_user = db.Column(db.ForeignKey('user.username'))
    message = db.Column(db.String(200))
    send_time = db.Column(db.DateTime)


class GroupMessage(db.Model):
    __tablename__ = "group_message"
    id = db.Column(db.Integer, primary_key=True)
    send_user = db.Column(db.ForeignKey('user.username'))
    gid = db.Column(db.ForeignKey('group.id'))
    message = db.Column(db.String(200))
    send_time = db.Column(db.DateTime)