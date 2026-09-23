import os
import secrets
from flask import Flask
from flask_login import LoginManager
from .db import get_db_connection

def create_app():
    app = Flask(__name__)
    # The secret key signs the login session cookie, so it must be long and random.
    # It is read from an environment variable if you set one;
    # otherwise a new random key is generated each time the server starts
    # (everyone simply has to log in again after a restart)
    # app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    app.config['SECRET_KEY'] = 'secret key'

    from .views import views
    from .auth import auth

    # url_preflex= --> mean how to access those url
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    # Message shown when someone who is not logged in opens a protected page
    login_manager.login_message = 'Please log in to access this page.'
    # Category 'Warning'
    login_manager.login_message_category = 'Warning'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.get(id)

    return app



