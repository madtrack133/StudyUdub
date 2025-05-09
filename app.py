# at the top, add these imports
import secrets
from werkzeug.utils import secure_filename
import re
import os
import logging
from logging.handlers import RotatingFileHandler
from io import BytesIO
from datetime import datetime
import base64
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request, session, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_mail import Mail, Message
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from email_validator import validate_email, EmailNotValidError
import pyotp
import qrcode

from config import Config
from models import db, Student, Notes, Course, Share

# --- Logging Configuration ---
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

file_handler = RotatingFileHandler('app.log', maxBytes=1_000_000, backupCount=3)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# --- Flask App Setup ---
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config.get('SECRET_KEY')
#Upload folder
UPLOAD_FOLDER = os.path.join(app.root_path, 'secure_notes')
ALLOWED_EXTENSIONS = {'md', 'pdf', 'txt', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --- Extensions ---
db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Helper Functions ---
def is_strong_password(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(pattern, password)

def allowed_file(filename):
    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

def map_category(cat):
    # map user read to database constraint check
    return {
        'Lecture Notes':      'Lecture',
        'Tutorials':          'Tutorial',
        'Past Exam Papers':   'Exam',
        'Assignment Solutions':'Other'
    }.get(cat, 'Other')


@login_manager.user_loader
def load_user(user_id):
    return Student.query.get(int(user_id))

# --- Auth Decorators ---
def twofa_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash("You must complete 2FA verification to access this page.", 'warning')
            return redirect(url_for('verify_2fa'))
        return view(**kwargs)
    return wrapped_view


# --- Email Senders ---
def send_password_reset_email(user):
    token = s.dumps(user.Email, salt='email-confirm')
    link = url_for('reset_password', token=token, _external=True)
    msg = Message('Reset Your Password', sender=app.config['MAIL_USERNAME'], recipients=[user.Email])
    msg.body = f"""Hi,\n\nTo reset your password, click below:\n{link}\n\nIf you didn’t request this, ignore this email."""
    mail.send(msg)

def send_2fa_reset_email(user):
    token = s.dumps(user.Email, salt='2fa-reset')
    link = url_for('reset_2fa_token', token=token, _external=True)
    msg = Message('Reset Your 2FA Key', sender=app.config['MAIL_USERNAME'], recipients=[user.Email])
    msg.body = f"""
Hi {user.FirstName},\n\nReset your 2FA key via:\n{link}\n\nThis expires in 1 hour.
"""
    mail.send(msg)

# --- Routes: Auth ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        confirm = request.form['confirm_password'].strip()
        first = request.form['first_name'].strip()
        last  = request.form['last_name'].strip()
        UniStudentID = request.form['uniStudentID'].strip()
        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            flash('Invalid email.', 'danger')
            return redirect(url_for('signup'))
        if password != confirm or not is_strong_password(password):
            flash('Password criteria not met or mismatch.', 'danger')
            return redirect(url_for('signup'))
        if Student.query.filter_by(Email=email).first():
            flash('Email already registered.', 'warning')
            return redirect(url_for('signup'))
        user = Student(Email=email, FirstName=first, LastName=last,UniStudentID=UniStudentID)
        user.set_password(password)
        db.session.add(user); db.session.commit()
        login_user(user)
        flash('Account created; complete 2FA setup.', 'success')
        return redirect(url_for('setup_2fa'))
    return render_template('signup.html')

@app.route('/setup-2fa', methods=['GET','POST'])
@login_required
def setup_2fa():
    if current_user.totp_secret:
        flash('2FA already set up.', 'info')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        logout_user(); flash('2FA setup complete; please log in.', 'success')
        return redirect(url_for('login'))
    secret = pyotp.random_base32()
    current_user.totp_secret = secret; db.session.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.Email, issuer_name='StudyApp')
    img = qrcode.make(uri)
    buf = BytesIO(); img.save(buf, 'PNG')
    qr = base64.b64encode(buf.getvalue()).decode()
    return render_template('setup_2fa.html', qr_code=qr, totp_secret=secret)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        pwd   = request.form['password'].strip()
        user  = Student.query.filter_by(Email=email).first()

        if user and user.check_password(pwd):
            login_user(user)
            #set your session flag so twofa_required passes
            session['user_id'] = user.StudentID
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'danger')

    return render_template('login.html')


@app.route('/verify-2fa', methods=['GET','POST'])
def verify_2fa():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    user = Student.query.get(session['temp_user_id'])
    if request.method == 'POST':
        code = request.form.get('code','').strip()
        if code == 'reset':
            session.clear(); send_2fa_reset_email(user)
            flash('Check email for 2FA reset.', 'info')
            return redirect(url_for('login'))
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code, valid_window=2):
            session['user_id'] = user.StudentID
            session.pop('temp_user_id', None)
            return redirect(url_for('dashboard'))
        flash('Invalid 2FA code.', 'danger')
    return render_template('verify_2fa.html')

@app.route('/reset-2fa-request', methods=['GET','POST'])
def reset_2fa_request():
    if request.method=='POST':
        email = request.form['email'].strip().lower()
        user  = Student.query.filter_by(Email=email).first()
        if user:
            send_2fa_reset_email(user)
            flash('2FA reset link sent.', 'info')
        else:
            flash('Email not found.', 'warning')
    return render_template('reset_2fa_request.html')

@app.route('/reset-2fa/<token>', methods=['GET','POST'])
def reset_2fa_token(token):
    try:
        email = s.loads(token, salt='2fa-reset', max_age=3600)
    except SignatureExpired:
        return '<h1>Link expired.</h1>'
    user = Student.query.filter_by(Email=email).first()
    if not user: return redirect(url_for('login'))
    if request.method=='POST':
        flash('2FA updated; please log in.', 'success')
        return redirect(url_for('login'))
    secret = pyotp.random_base32(); user.totp_secret = secret; db.session.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.Email, issuer_name='StudyApp')
    img = qrcode.make(uri); buf = BytesIO(); img.save(buf,'PNG')
    qr = base64.b64encode(buf.getvalue()).decode()
    return render_template('setup_2fa.html', qr_code=qr, totp_secret=secret)

@app.route('/forgot', methods=['GET','POST'])
def forgot():
    if request.method=='POST':
        email = request.form['email'].strip().lower()
        user  = Student.query.filter_by(Email=email).first()
        if user:
            send_password_reset_email(user)
            flash('Password reset sent.', 'info')
        else:
            flash('Email not found.', 'warning')
    return render_template('forgot_password.html')

@app.route('/reset/<token>', methods=['GET','POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>Link expired.</h1>'
    user = Student.query.filter_by(Email=email).first() or redirect(url_for('login'))
    if request.method=='POST':
        pwd = request.form['password']; cpwd = request.form['confirm_password']
        if pwd!=cpwd or not is_strong_password(pwd):
            flash('Criteria not met.', 'danger')
            return redirect(request.url)
        user.set_password(pwd); db.session.commit()
        flash('Password reset! Log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); session.clear()
    return redirect(url_for('login'))

# --- Routes: Main Application ---
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
@twofa_required
def dashboard():
    return render_template('dashboard.html', courses=session.get('courses', []), user=current_user)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@twofa_required
def upload():
    if request.method == 'POST':
        title       = request.form['title'].strip()
        raw_cat     = request.form['category']
        course_code = request.form['course']
        file        = request.files.get('file')

        if not file or not allowed_file(file.filename):
            flash('Invalid file type. Allowed: .md, .pdf, .txt, .docx', 'danger')
            return redirect(request.url)

        # generate 64-hex-char prefix (meets your CHECK constraint)
        prefix   = secrets.token_hex(32)
        filename = secure_filename(file.filename)
        save_name = f"{prefix}_{filename}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], save_name)
        file.save(save_path)

        # look up the course in the DB (nullable if not found)
        course = Course.query.filter_by(UnitCode=course_code).first()
        course_id = course.CourseID if course else None

        note = Notes(
            StudentID=current_user.StudentID,
            CourseID=course_id,
            Title=title,
            Category=map_category(raw_cat),
            Description='',
            FilePath=f"/secure_notes/{save_name}"
        )
        db.session.add(note)
        db.session.commit()

        flash('Note uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))

    # GET renders the same form
    return render_template('upload.html', courses=session.get('courses', []))

@app.route('/share')
@login_required
@twofa_required
def share():
    if request.method == 'POST':
        note_id     = int(request.form['note_id'])
        accessee_id = int(request.form['accessee_id'])

        note = Notes.query.get(note_id)
        if not note or note.StudentID != current_user.StudentID:
            flash('Cannot share a note you do not own.', 'danger')
            return redirect(url_for('share'))

        student = Student.query.get(accessee_id)
        if not student:
            flash('Student ID not found.', 'warning')
            return redirect(url_for('share'))

        existing = Share.query.filter_by(
            NoteID=note_id, AccesseeStudentID=accessee_id
        ).first()
        if existing:
            flash('Note already shared with that student.', 'info')
        else:
            new_share = Share(
                NoteID=note_id,
                OwnerStudentID=current_user.StudentID,
                AccesseeStudentID=accessee_id,
                EditPower=0
            )
            db.session.add(new_share)
            db.session.commit()
            flash('Note shared successfully!', 'success')

        return redirect(url_for('share'))
    # GET: gather lists for the template
    owned_notes  = Notes.query.filter_by(StudentID=current_user.StudentID).all()
    shared_notes = [
        s.note for s in Share.query.filter_by(AccesseeStudentID=current_user.StudentID).all()
    ]
    return render_template(
        'share.html',
        owned_notes=owned_notes,
        shared_notes=shared_notes,
        courses=session.get('courses', [])
    )
@app.route('/download/<int:note_id>')
@login_required
@twofa_required
def download(note_id):
    note = Notes.query.get_or_404(note_id)
    is_owner = (note.StudentID == current_user.StudentID)
    is_shared = Share.query.filter_by(
        NoteID=note_id, AccesseeStudentID=current_user.StudentID
    ).first() is not None

    if not (is_owner or is_shared):
        abort(403)

    # FilePath is stored as "/secure_notes/<filename>"
    filename = os.path.basename(note.FilePath)
    directory = os.path.join(app.root_path, 'secure_notes')
    return send_from_directory(directory, filename, as_attachment=True)
@app.route('/shared_with_me')
@login_required
@twofa_required
def shared_with_me():
    return render_template('shared_with_me.html', courses=session.get('courses', []))

@app.route('/deadlines')
@login_required
@twofa_required
def deadlines():
    return render_template('deadlines.html', courses=session.get('courses', []))

@app.route('/course/<course_code>')
@login_required
@twofa_required
def course_notes(course_code):
    return render_template('course_notes.html', course_code=course_code, courses=session.get('courses', []))

@app.route('/add_course', methods=['POST'])
@login_required
@twofa_required
def add_course():
    code = request.form['course_code']
    if 'courses' not in session: session['courses'] = []
    if not any(c['code']==code for c in session['courses']): session['courses'].append({'code':code})
    session.modified = True
    return redirect(url_for('dashboard'))

@app.route('/grades', methods=['GET', 'POST'])
@login_required
@twofa_required
def grades_view():
    if 'grades' not in session:
        session['grades'] = []

    if request.method == 'POST':
        unit = request.form['unit']
        assessment = request.form['assessment']
        score = float(request.form['score'])
        out_of = float(request.form['out_of'])
        weight = float(request.form['weight'])

        contribution = round((score / out_of) * weight, 2)

        session['grades'].append({
            'unit': unit,
            'assessment': assessment,
            'score': score,
            'out_of': out_of,
            'weight': weight,
            'contribution': contribution
        })
        session.modified = True

    # Group grades by unit and calculate summary
    summaries = {}
    chart_data = {}

    for g in session['grades']:
        unit = g['unit']
        summaries.setdefault(unit, {'achieved': 0.0})
        summaries[unit]['achieved'] += g['contribution']

        chart_data.setdefault(unit, {'labels': [], 'values': []})
        chart_data[unit]['labels'].append(g['assessment'])
        chart_data[unit]['values'].append(g['contribution'])

    session['summaries'] = summaries

    return render_template(
        'grades.html',
        grades=session['grades'],
        summaries=summaries,
        chart_data=chart_data,
        courses=session.get('courses', [])
    )

if __name__ == '__main__':
    app.run(debug=True)
