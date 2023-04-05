from flask import Flask, render_template, session, request, url_for, redirect, jsonify, make_response, flash
import random
import string
import time
import secrets
import sqlite3
from functools import wraps
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler
from flask_bcrypt import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sslify import SSLify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils import generate_secret_key, schedule_secret_key_regeneration
import config

conn = sqlite3.connect('registration.db')
c = conn.cursor()
app = Flask(__name__, static_url_path='/static')
app.config.update(config.__dict__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['SECRET_KEY'] = generate_secret_key()
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'akram21uu@gmail.com' 
app.config['MAIL_PASSWORD'] = 'easesvxuxzxnzuda'
app.config['MAIL_DEFAULT_SENDER'] = 'akram21uu@gmail.com'

schedule_secret_key_regeneration(app)
print(app.config['SECRET_KEY'])
mail = Mail(app)
limiter = Limiter(app, default_limits=["10 per minute"])


@app.before_first_request
def initialize():
    app.secret_key = generate_secret_key()
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=generate_secret_key, trigger='interval', minutes=5)
    scheduler.start()

def generate_secret_key():
    return secrets.token_hex(16)


def generate_verification_code(length=4):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join((random.choice(letters_and_digits) for i in range(length)))

def create_database():
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            verified TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

@app.route('/', methods=['GET'])
def redirectoreg():
    return redirect(url_for('registration'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
@limiter.exempt
def registration():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('registration.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email=?', (email,))
        user = c.fetchone()
        
        if user:
            response = {'message': 'User already exists'}
            return jsonify(response), 400
        
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, password))
        conn.commit()
        conn.close()
        
        
        return 201
        
    return render_template('register.html')


@app.route('/confirm_email', methods=['GET', 'POST'])
def confirm_email():
    if 'registered' not in session:
        return redirect(url_for('registration'))
    if request.method == 'POST':
        verification_code = request.form.get('verification_code')
        if verification_code == session['verification_code']:
            return redirect(url_for('dashboard_page'))
        else:
            error_message = 'Incorrect verification code, please try again.'
            return render_template('confirm_email.html', error_message=error_message)
    return render_template('confirm_email.html')




def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        email = request.cookies.get('email')
        password = request.cookies.get('password')
        conn = sqlite3.connect('registration.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email=? AND password=?', (email, password))
        user = c.fetchone()
        conn.close()
        if user is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = sqlite3.connect('registration.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email=?', (email,))
        user = c.fetchone()
        conn.close()

        if user is None:
            response = {'message': 'Invalid email or password'}
            return jsonify(response), 401
        else:
            stored_password = user[3]
            if password == stored_password:
                username = user[1]
                return redirect(url_for('dashboard_page', username=username))
            else:
                response = {'message': 'Invalid email or password'}
                return jsonify(response), 401

    return render_template('login.html')


@app.route('/<username>/dashboard', methods=['GET'])
def dashboard_page(username):
    notifications = 2

    return render_template('dashboard.html', username=username, notifications=notifications)

@app.errorhandler(429)
def ratelimit_handler(e):
    return redirect(url_for('rate_limit_exceeded'))


@app.route('/rate_limit_exceeded')
def rate_limit_exceeded():
    return render_template('rate_limit_exceeded.html')

if __name__ == '__main__':
    create_database()
    app.run(debug=True)
