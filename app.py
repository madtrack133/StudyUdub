import re
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from email_validator import validate_email, EmailNotValidError
from models import db, Student
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)
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

        # Need FirstName and LastName for Student model
        # For now, let's add placeholders or prompt user - using placeholders for now
        # Ideally, the signup form should collect these.
        user = Student(Email=email, FirstName=first_name, LastName=last_name) # Updated
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        user = Student.query.filter_by(Email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid login credentials.')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
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
def dashboard():
    return f"<h1>Welcome, {current_user.Email}!</h1><a href='/logout'>Logout</a>"

if __name__ == '__main__':
    app.run(debug=True)
