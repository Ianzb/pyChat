from flask import Flask, render_template, request, jsonify
from config import BaseConfig
from flask_sqlalchemy import SQLAlchemy
from model import *
import time


app = Flask(__name__)

app.config.from_object(BaseConfig)
with app.app_context():
    db.init_app(app)
    db.drop_all()
    db.create_all()


@app.route('/')
def index():  # put application's code here
    return render_template('index.html')


@app.route('/api/v1/register_app', methods=['POST'])
def register_app():
    request_data = request.get_json()
    description = request_data.get('description')
    response_data = {'app_id': time.time(), 'status': 0}
    return jsonify(response_data)


@app.route('/api/v1/heartbeat', methods=['POST'])
def heartbeat():
    request_data = request.get_json()
    timestamp = request_data.get('timestamp')
    app_id = request_data.get('app_id')
    response_data = {'timestamp': time.time(), 'status': 0}
    return jsonify(response_data)


if __name__ == '__main__':
    app.run()
