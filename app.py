from flask import Flask, request, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import os
import re
from datetime import datetime

# Initialize Flask application
app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS = False,
    SECRET_KEY = os.urandom(32),
    SECURITY_PASSWORD_SALT = os.urandom(32),
    SESSION_COOKIE_SECURE = True,
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax',
    WTF_CSRF_ENABLED = True,
    # Add recommended security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN'
    }
)

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)

# Models
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    active = db.Column(db.Boolean(), default=True)
    # Add required Flask-Security field
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    failed_login_count = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    roles = db.relationship('Role', secondary=roles_users, 
                          backref=db.backref('users', lazy='dynamic'))

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.after_request
def add_security_headers(response):
    """Add security headers to every response"""
    for header, value in app.config['SECURITY_HEADERS'].items():
        response.headers[header] = value
    return response

def init_db():
    with app.app_context():
        db.create_all()
        # Create default roles if they don't exist
        if not Role.query.first():
            user_role = Role(name='user', description='Regular user role')
            admin_role = Role(name='admin', description='Administrator role')
            db.session.add(user_role)
            db.session.add(admin_role)
            db.session.commit()

def generate_uniquifier():
    """Generate a unique identifier for Flask-Security"""
    return os.urandom(24).hex()

def hash_password(password):
    """Hash a password with bcrypt using higher work factor"""
    salt = bcrypt.gensalt(rounds=12)  # Increased rounds for better security
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed):
    """Verify a password against a hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    except Exception:
        return False

def is_valid_password(password):
    """Validate password strength with improved requirements"""
    if len(password) < 12:  # Increased minimum length
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*]', password):
        return False
    # Check for common passwords (you should expand this list)
    common_passwords = ['Password123!', 'Admin123!', 'Welcome123!']
    if password in common_passwords:
        return False
    return True

def is_valid_email(email):
    """Validate email format with improved regex"""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email)) and len(email) <= 255

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('register'))

        if not is_valid_email(email):
            flash('Invalid email format', 'error')
            return redirect(url_for('register'))

        if not is_valid_password(password):
            flash('Password does not meet security requirements', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            # Use generic message to prevent user enumeration
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register'))

        try:
            hashed_password = hash_password(password)
            new_user = User(
                email=email,
                password=hashed_password,
                fs_uniquifier=generate_uniquifier()
            )
            # Assign default user role
            default_role = Role.query.filter_by(name='user').first()
            if default_role:
                new_user.roles.append(default_role)
                
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        
        if not user or user.account_locked:
            # Use generic message to prevent user enumeration
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))

        if not verify_password(password, user.password):
            user.failed_login_count += 1
            if user.failed_login_count >= 5:
                user.account_locked = True
                # Use generic message to prevent user enumeration
                flash('Invalid credentials', 'error')
            else:
                flash('Invalid credentials', 'error')
            db.session.commit()
            return redirect(url_for('login'))

        # Successful login
        user.failed_login_count = 0
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return "Welcome to your dashboard!"

if __name__ == '__main__':
    init_db()
    app.run(ssl_context='adhoc', debug=False)  # Enable HTTPS and disable debug mode in production