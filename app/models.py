from . import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    elo = db.Column(db.Integer, default=501)
    enabled = db.Column(db.Boolean, default=False)
    matches_played = db.Column(db.Integer, default=0)
    matches_won = db.Column(db.Integer, default=0)
    matches_lost = db.Column(db.Integer, default=0)
    one_eighties = db.Column(db.Integer, default=0)
    high_finishes = db.Column(db.Integer, default=0)  # 100+ finishes
    highest_finish = db.Column(db.Integer, default=0)  # Highest checkout score
    last_played = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    winner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    loser_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    winner_elo_gain = db.Column(db.Integer, nullable=False)
    loser_elo_loss = db.Column(db.Integer, nullable=False)
    date_played = db.Column(db.DateTime, default=datetime.utcnow)
    recorded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    winner_180s = db.Column(db.Integer, default=0)
    loser_180s = db.Column(db.Integer, default=0)
    winning_finish = db.Column(db.Integer, default=0)  # The checkout score
    # Comma-separated list of all leg finishing checkout scores for each player (optional new feature)
    winner_finishes = db.Column(db.String, default="")
    loser_finishes = db.Column(db.String, default="")

    winner = db.relationship('User', foreign_keys=[winner_id], backref='matches_won_list')
    loser = db.relationship('User', foreign_keys=[loser_id], backref='matches_lost_list')
    recorder = db.relationship('User', foreign_keys=[recorded_by], backref='matches_recorded_list')

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='reset_tokens')
    
    def __init__(self, user_id):
        self.user_id = user_id
        self.token = secrets.token_urlsafe(32)
        self.expires_at = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    
    def is_valid(self):
        return not self.used and datetime.utcnow() < self.expires_at
    
    def mark_as_used(self):
        self.used = True
