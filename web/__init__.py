"""
PyForensix Web — Flask + SocketIO application factory.
"""
from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO()


def create_app() -> Flask:
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config['SECRET_KEY'] = os.urandom(32).hex()

    socketio.init_app(app, cors_allowed_origins='*', async_mode='threading')

    from web.routes.api import api_bp
    from web.routes.dashboard import dash_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(dash_bp)

    return app


import os
