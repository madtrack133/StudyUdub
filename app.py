import re
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from email_validator import validate_email, EmailNotValidError
from models import db, Student
from config import Config
from datetime import datetime
import pyotp
import qrcode
import os
import base64
from io import BytesIO
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps


# --- Logging Configuration ---
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

file_handler = RotatingFileHandler('app.log', maxBytes=1_000_000, backupCount=3)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)

# Add handler to root logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db) #db versioning
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/')
def home():
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return Student.query.get(int(user_id))

def send_password_reset_email(mail, user):
    token = s.dumps(user.Email, salt='email-confirm')
    link = url_for('reset_password', token=token, _external=True)

    msg = Message('Reset Your Password',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.Email])
    msg.body = f"""Hi,

To reset your password, click the link below:
{link}

If you didn’t request this, just ignore this email.
"""
    mail.send(msg)
    
def send_2fa_reset_email(mail, user):
    token = s.dumps(user.Email, salt='2fa-reset')
    link = url_for('reset_2fa_token', token=token, _external=True)

    msg = Message('Reset Your 2FA Key',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.Email])
    msg.body = f'''Hi {user.Email},

We received a request to reset your Two-Factor Authentication (2FA) key for your account on StudyApp.

If you initiated this request, click the link below to reset your 2FA key and set up a new one:

{link}

This link will expire in 1 hour for security reasons.

If you did not request this, you can safely ignore this email — your 2FA settings will remain unchanged.

Thanks,  
StudyApp Team
'''
    mail.send(msg)

def twofa_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash("You must complete 2FA verification to access this page.")
            return redirect(url_for('verify_2fa'))
        return view(**kwargs)
    return wrapped_view

# Helper function to validate strong passwords
def is_strong_password(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(pattern, password)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        first_name = request.form['first_name'].strip() # Added
        last_name = request.form['last_name'].strip()   # Added

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            flash('Please enter a valid email address.')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('signup'))

        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.')
            return redirect(url_for('signup'))

        existing_user = Student.query.filter_by(Email=email).first()
        if existing_user:
            flash('An account with that email already exists.')
            return redirect(url_for('signup'))

        user = Student(Email=email, FirstName=first_name, LastName=last_name) # Updated
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Account created successfully! Please set up 2FA.')
        return redirect(url_for('setup_2fa'))

    return render_template('signup.html')

@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.totp_secret:
        flash("2FA is already set up.")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        flash("2FA setup complete. Please log in.")
        logout_user()
        return redirect(url_for('login'))

    # If user dosen't have 2FA set up yet, set it up here
    new_secret = pyotp.random_base32()
    current_user.totp_secret = new_secret
    db.session.commit()

    totp = pyotp.TOTP(new_secret)
    uri = totp.provisioning_uri(name=current_user.Email, issuer_name="StudyApp")

    img = qrcode.make(uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template("setup_2fa.html", qr_code=qr_base64, totp_secret=new_secret)


# --- Reset 2FA ---
@app.route('/reset-2fa-request', methods=['GET', 'POST'])
def reset_2fa_request():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = Student.query.filter_by(Email=email).first()
        if user:
            send_2fa_reset_email(mail, user)
            flash("A reset link to set up new 2FA was sent to your email.")
        else:
            flash("No account found with that email.")
    return render_template("reset_2fa_request.html")


# --- Reset 2FA Token ---
@app.route('/reset-2fa/<token>', methods=['GET', 'POST'])
def reset_2fa_token(token):
    try:
        email = s.loads(token, salt='2fa-reset', max_age=3600)
    except SignatureExpired:
        return "<h1>The reset link has expired.</h1>"

    user = Student.query.filter_by(Email=email).first()
    if not user:
        flash("Invalid or expired token.")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        flash("2FA reset complete. Please log in.")
        return redirect(url_for('login'))

    # Generate new otp key
    new_secret = pyotp.random_base32()
    user.totp_secret = new_secret
    db.session.commit()

    # Genarate QR Code
    totp = pyotp.TOTP(new_secret)
    uri = totp.provisioning_uri(name=user.Email, issuer_name="StudyApp")

    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template("setup_2fa.html", qr_code=qr_base64, totp_secret=new_secret)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        user = Student.query.filter_by(Email=email).first()
        if user and user.check_password(password):
            login_user(user)
            
            # Check if user has 2FA set up
            if not user.totp_secret:
                flash("2FA is not set up. Please complete setup.")
                return redirect(url_for('setup_2fa'))
            
            # --- Two-Factor Authentication (2FA) ---
            session['temp_user_id'] = user.StudentID  # Store user ID temporarily for 2FA
            logging.info(f"User {user.Email} logged in - redirecting to 2FA verification")
            return redirect(url_for('verify_2fa'))
        flash('Invalid login credentials.')

    return render_template('login.html')

# ---- Two-Factor Authentication (2FA) ---
@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user_id' not in session:
        logging.warning("No temp_user_id in session – redirecting to login.")
        return redirect(url_for('login'))

    user = Student.query.get(session['temp_user_id'])
    logging.info(f"Found student with ID: {user.StudentID}")

    if request.method == 'POST':
        action = request.form.get('action')
        
        # --- Forget 2FA key ---
        if action == 'reset':
            flash("2FA key has been reset. Please check your email to set up a new key.")
            session.clear()
            return redirect(url_for('reset_2fa_request'))
        
        # --- Verify 2FA code ---
        elif action == 'verify':
            user_code = request.form.get('code', '').strip()
            if len(user_code) != 6 or not user_code.isdigit():
                logging.warning("Invalid code format received during 2FA verification.")
                return render_template('verify_2fa.html', error="Invalid code format")

            try:
                totp = pyotp.TOTP(user.totp_secret)
                current_time = datetime.now().timestamp()
                logging.debug(f"Current server time: {datetime.now()}")
                is_valid = totp.verify(user_code, valid_window=2)
                logging.debug(f"2FA verification for user ID {user.StudentID} ({user.Email}): {is_valid}")

                if is_valid:
                    session['user_id'] = user.StudentID
                    session.pop('temp_user_id', None)
                    logging.info(f"Login successful for user ID {user.StudentID} ({user.Email}) - redirecting to dashboard")
                    return redirect(url_for('dashboard'))
                
                logging.warning(f"Invalid 2FA code attempt for user ID {user.StudentID} ({user.Email})")
                return render_template('verify_2fa.html', error="Invalid verification code")
            
            except Exception as e:
                logging.exception(f"Verification error for user ID {user.StudentID} ({user.Email})")
                return render_template('verify_2fa.html', error="Verification failed")

    return render_template('verify_2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = Student.query.filter_by(Email=email).first()
        if user:
            send_password_reset_email(mail, user)
            flash('Password reset link sent to your email.')
        else:
            flash('No account found with that email.')
    return render_template('forgot_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The reset link has expired.</h1>'

    user = Student.query.filter_by(Email=email).first()
    if not user:
        flash('Invalid or expired token.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        if new_password != confirm_password:
            flash('Passwords do not match.')
            return redirect(request.url)

        if not is_strong_password(new_password):
            flash('Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.')
            return redirect(request.url)

        user.set_password(new_password)
        db.session.commit()
        flash('Password has been reset. You may now log in.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
@twofa_required
def dashboard():
    return f"<h1>Welcome, {current_user.Email}!</h1><a href='/logout'>Logout</a>"

if __name__ == '__main__':
    app.run(debug=True)
