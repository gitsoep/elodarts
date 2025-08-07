from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
import os
from dotenv import load_dotenv

load_dotenv()
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///elodarts.db')
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'your-mail-server')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'email-username')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
    mail.init_app(app)
    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    
    from .routes import main
    app.register_blueprint(main)
    
    return app
