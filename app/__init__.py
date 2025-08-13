from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
import os
import logging
from logging.handlers import RotatingFileHandler
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
    
    # Configure logging
    if not app.debug:
        # Ensure logs directory exists
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        # Set up rotating file handler
        file_handler = RotatingFileHandler('logs/elodarts.log', maxBytes=10240000, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('ELO Darts application startup')
    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    
    from .routes import main
    app.register_blueprint(main)
    
    # Initialize database only if it doesn't exist
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    if db_uri.startswith('sqlite:///'):
        # Extract database file path
        db_path = db_uri.replace('sqlite:///', '')
        if not os.path.isabs(db_path):
            db_path = os.path.join(app.instance_path, db_path)
        
        # Only initialize if database file doesn't exist
        if not os.path.exists(db_path):
            # Ensure instance directory exists
            os.makedirs(app.instance_path, exist_ok=True)
            with app.app_context():
                init_database()
    
    return app

def init_database():
    """Initialize database tables and create default admin user."""
    from .models import User
    
    # Create all tables
    db.create_all()
    
    # Create admin user
    admin_user = User(
        username='admin',
        email='admin@example.com',
        admin=True,
        enabled=True,
        elo=1000
    )
    admin_user.set_password('admin')
    db.session.add(admin_user)
    db.session.commit()
    print("Created new database with default admin user (username: admin, password: admin)")
