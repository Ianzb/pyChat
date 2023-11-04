from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Application(db.Model):
    __tablename__ = "application"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.String(10))
    app_key = db.Column(db.String(20))
    description = db.Column(db.String(50))
    reg_time = db.Column(db.Integer)  # timestamp
    last_use_time = db.Column(db.Integer)  # timestamp


class User(db.Model):
    __tablename__ = "user"
