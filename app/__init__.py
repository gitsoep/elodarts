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
    
    # Initialize database and create admin user if needed
    with app.app_context():
        init_database()
    
    return app

def init_database():
    """Initialize database tables and create default admin user if needed."""
    from .models import User
    
    # Create all tables
    db.create_all()
    
    # Check if admin user exists
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
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
        print("Created default admin user (username: admin, password: admin)")
