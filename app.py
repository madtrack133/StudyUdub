from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from email_validator import validate_email, EmailNotValidError
from models import db, User
from config import Config

# --- Flask App Setup ---
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Home redirects to login ---
@app.route('/')
def home():
    return redirect(url_for('login'))

# --- Flask-Login: Load user by ID ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper: Send Password Reset Email ---
def send_password_reset_email(mail, user):
    token = s.dumps(user.email, salt='email-confirm')
    link = url_for('reset_password', token=token, _external=True)

    msg = Message('Reset Your Password',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''Hi,

To reset your password, click the link below:
{link}

If you didn’t request this, just ignore this email.
'''
    mail.send(msg)

# --- Signup ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        #validate email format
        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            flash('Please enter a valid email address.')
            return redirect(url_for('signup'))

        #check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('signup'))

        #check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('An account with that email already exists.')
            return redirect(url_for('signup'))

        #create the user
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully!')
        return redirect(url_for('login'))

    return render_template('signup.html')


# --- Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid login credentials.')

    return render_template('login.html')

# --- Logout ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Forgot Password ---
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(mail, user)
            flash('Password reset link sent to your email.')
        else:
            flash('No account found with that email.')
    return render_template('forgot_password.html')

# --- Reset Password ---
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The reset link has expired.</h1>'

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid or expired token.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password'].strip()
        user.set_password(new_password)
        db.session.commit()
        flash('Password has been reset. You may now log in.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# --- Dashboard (Protected) ---
@app.route('/dashboard')
@login_required
def dashboard():
    return f"<h1>Welcome, {current_user.email}!</h1><a href='/logout'>Logout</a>"

# --- Run the app ---
if __name__ == '__main__':
    app.run(debug=True)
