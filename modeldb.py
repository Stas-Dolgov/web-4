from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

db = SQLAlchemy()  # Инициализируем SQLAlchemy


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text)
    users = db.relationship('User', backref='role', lazy=True)  # Связь с User

    def __repr__(self):
        return f'<Role {self.name}>'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=True)
    middle_name = db.Column(db.String(50), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class VisitLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='visit_logs')

    def __repr__(self):
        return f'<VisitLog {self.path} - {self.created_at}>'

    @property
    def user_info(self):
        if self.user:
            return f"{self.user.last_name or ''} {self.user.first_name or ''} {self.user.middle_name or ''}"
        return "Неаутентифицированный пользователь"
    
    @property
    def formatted_time(self):
        timezone = pytz.timezone('Europe/Moscow') 
        return self.created_at.replace(tzinfo=pytz.utc).astimezone(timezone).strftime('%d.%m.%Y %H:%M:%S')
