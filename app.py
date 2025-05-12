import os
import re
import secrets
import logging
from logging.handlers import RotatingFileHandler
from io import BytesIO
from datetime import datetime
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_from_directory, abort
)
from flask_wtf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from flask_mail import Mail, Message
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from email_validator import validate_email, EmailNotValidError
import pyotp, qrcode

from config import Config
from models import db, Student, Notes, Course, Share, Assignment

# ── App + CSRF Setup ─────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)    # SECRET_KEY, DATABASE_URI, MAIL_*, etc.
CSRFProtect(app)                  # all POSTs now require a valid csrf_token

# ── Logging ──────────────────────────────────────
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
fh = RotatingFileHandler('app.log', maxBytes=1_000_000, backupCount=3)
fh.setFormatter(formatter)
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(ch)

# ── Extensions ────────────────────────────────────
db.init_app(app)
migrate = Migrate(app, db)
mail    = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ── Helpers & Decorators ─────────────────────────
def is_strong_password(pw):
    return re.match(
      r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$',
      pw
    )

def allowed_file(fn):
    return '.' in fn and fn.rsplit('.',1)[1].lower() in {'md','pdf','txt','docx'}

def map_category(cat):
    return {
      'Lecture Notes':'Lecture',
      'Tutorials':'Tutorial',
      'Past Exam Papers':'Exam',
      'Assignment Solutions':'Other'
    }.get(cat,'Other')

@login_manager.user_loader
def load_user(user_id):
    return Student.query.get(int(user_id))

def twofa_required(f):
    @wraps(f)
    def wrapped(*args,**kwargs):
        if 'user_id' not in session:
            flash("Complete 2FA first.", 'warning')
            return redirect(url_for('verify_2fa'))
        return f(*args,**kwargs)
    return wrapped

def send_password_reset_email(user):
    token = serializer.dumps(user.Email, salt='email-confirm')
    link = url_for('reset_password', token=token, _external=True)
    msg = Message('Reset Your Password',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.Email])
    msg.body = f"Hi,\n\nReset at: {link}"
    mail.send(msg)

def send_2fa_reset_email(user):
    token = serializer.dumps(user.Email, salt='2fa-reset')
    link = url_for('reset_2fa_token', token=token, _external=True)
    msg = Message('Reset Your 2FA Key',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.Email])
    msg.body = f"Hi {user.FirstName}, reset here:\n{link}"
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
        flash('2FA is already configured. Please log in.', 'info')
        logout_user()
        return redirect(url_for('login'))
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
            #set your session flag so twofa_required passes
            session['temp_user_id'] = user.StudentID
            flash('Logged in successfully!', 'success')
            return redirect(url_for('verify_2fa'))

        flash('Invalid email or password.', 'danger')

    return render_template('login.html')


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
                logging.debug(f"2FA verification for user ID {user.StudentID} : {is_valid}")

                if is_valid:
                    login_user(user)
                    session['user_id'] = user.StudentID
                    session.pop('temp_user_id', None)
                    logging.info(f"Login successful for user ID {user.StudentID}) - redirecting to dashboard")
                    return redirect(url_for('dashboard'))

                logging.warning(f"Invalid 2FA code attempt for user ID {user.StudentID} ({user.Email})")
                return render_template('verify_2fa.html', error="Invalid verification code")

            except Exception as e:
                logging.exception(f"Verification error for user ID {user.StudentID} ({user.Email})")
                return render_template('verify_2fa.html', error="Verification failed")

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
    all_courses = Course.query.order_by(Course.UnitCode).all()
    return render_template('upload.html', courses=all_courses)

@app.route('/share', methods=['GET', 'POST'])
@login_required
@twofa_required
def share():
    if request.method == 'POST':
        note_id    = int(request.form['note_id'])
        uni_id     = request.form['accessee_uni_id'].strip()

        # verify ownership
        note = Notes.query.get(note_id)
        if not note or note.StudentID != current_user.StudentID:
            flash('Cannot share a note you do not own.', 'danger')
            return redirect(url_for('share'))

        # look up the student by UniStudentID, not PK
        student = Student.query.filter_by(UniStudentID=uni_id).first()
        if not student:
            flash(f"No student found with UniStudentID '{uni_id}'.", 'warning')
            return redirect(url_for('share'))
        accessee_id = student.StudentID

        # prevent duplicates
        existing = Share.query.filter_by(
            NoteID=note_id,
            AccesseeStudentID=accessee_id
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
    # pull all Share records for this user
    shares = Share.query.filter_by(AccesseeStudentID=current_user.StudentID).all()

    # build a list of dicts for the template
    shared_docs = []
    for share in shares:
        note  = share.note
        owner = share.owner
        shared_docs.append({
            'id':        note.NoteID,
            'title':     note.Title,
            'shared_by': f"{owner.FirstName} {owner.LastName}"
        })

    return render_template(
        'shared_with_me.html',
        shared_docs=shared_docs,
        courses=session.get('courses', [])
    )


@app.route('/deadlines', methods=['GET', 'POST'])
@login_required
def deadlines():
    if request.method == 'POST':
        # distinguish “add” vs “toggle done” by a hidden field
        if 'new_deadline' in request.form:
            # add new
            unit_code   = request.form['unit_code'].strip().upper()
            name        = request.form['task'].strip()
            due_date    = datetime.strptime(request.form['due_date'], '%Y-%m-%d').date()
            course = Course.query.filter_by(UnitCode=unit_code).first()
            if not course:
                flash(f"Unit '{unit_code}' not found.", 'danger')
            else:
                a = Assignment(
                  AssignmentName = name,
                  CourseID       = course.CourseID,
                  StudentID      = current_user.StudentID,
                  HoursSpent     = 0.0,
                  Weight         = 0.0,
                  MarksAchieved  = 0.0,
                  MarksOutOf     = 1.0,
                  DueDate        = due_date,
                  Completed      = False
                )
                db.session.add(a)
                db.session.commit()
                flash('Deadline added.', 'success')
        elif 'toggle_id' in request.form:
            # toggle completed
            aid = int(request.form['toggle_id'])
            a = Assignment.query.get_or_404(aid)
            if a.StudentID == current_user.StudentID:
                a.Completed = not a.Completed
                db.session.commit()
                flash('Updated status.', 'success')
            else:
                flash("Permission denied.", 'danger')
        return redirect(url_for('deadlines'))

    # GET: fetch upcoming vs done
    upcoming = Assignment.query.filter_by(
        StudentID=current_user.StudentID, Completed=False
    ).order_by(Assignment.DueDate).all()
    done = Assignment.query.filter_by(
        StudentID=current_user.StudentID, Completed=True
    ).order_by(Assignment.DueDate.desc()).all()

    return render_template(
      'deadlines.html',
      upcoming=upcoming,
      done=done
    )


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
    if request.method == 'POST':
        try:
            # Read and validate form inputs
            unit_code    = request.form['unit'].strip().upper()
            assessment   = request.form['assessment'].strip()
            score        = float(request.form['score'])
            out_of       = float(request.form['out_of'])
            weight       = float(request.form['weight'])

            #enforce non negative score, positive out_of, and weight 0-100
            if score < 0 or out_of <= 0 or not (0 <= weight <= 100):
                flash('Invalid input: Score must be ≥ 0; Out Of must be > 0; Weight 0–100%', 'danger')
                return redirect(url_for('grades_view'))

            # Parse the due date
            due_date_str = request.form['due_date']
            due_date     = datetime.strptime(due_date_str, '%Y-%m-%d').date()


            # Look up the course
            course = Course.query.filter_by(UnitCode=unit_code).first()
            if not course:
                flash(f"Unit code '{unit_code}' not found. Please add it first.", 'danger')
                return redirect(url_for('grades_view'))

            # Create and save the assignment
            assignment = Assignment(
                AssignmentName = assessment,
                CourseID       = course.CourseID,
                StudentID      = current_user.StudentID,
                HoursSpent     = 0.0,
                Weight         = weight,
                MarksAchieved  = score,
                MarksOutOf     = out_of,
                DueDate        = due_date
            )
            db.session.add(assignment)
            db.session.commit()
            flash('Assignment saved!', 'success')

        except Exception as e:
            db.session.rollback()
            flash(f'Error saving assignment: {e}', 'danger')

    # Fetch all assignments for this student, ordered by due date
    assignments = (
        Assignment.query
        .filter_by(StudentID=current_user.StudentID)
        .join(Course)
        .order_by(Assignment.DueDate)
        .all()
    )

    # Build summaries & per‐unit date lists
    summaries = {}
    temp = defaultdict(lambda: defaultdict(list))
    for a in assignments:
        unit = a.course.UnitCode
        pct  = (a.MarksAchieved / a.MarksOutOf) * 100
        temp[unit][a.DueDate].append(pct)

        summaries.setdefault(unit, {'achieved': 0.0})
        summaries[unit]['achieved'] += round((a.MarksAchieved / a.MarksOutOf) * a.Weight, 2)

    # Compute cumulative averages per date
    chart_data = {}
    for unit, dates in temp.items():
        sorted_dates = sorted(dates.keys())
        labels = [d.isoformat() for d in sorted_dates]

        # Per‐date average
        per_date = [round(sum(dates[d]) / len(dates[d]), 2) for d in sorted_dates]

        # Running cumulative average
        cum_vals = []
        running = 0.0
        for i, v in enumerate(per_date):
            running += v
            cum_vals.append(round(running / (i + 1), 2))

        chart_data[unit] = {'labels': labels, 'values': cum_vals}

    return render_template(
        'grades.html',
        grades     = assignments,
        summaries  = summaries,
        chart_data = chart_data,
        courses    = session.get('courses', [])
    )


@app.route('/grades/delete/<int:assignment_id>', methods=['POST'])
@login_required
def delete_assignment(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    # ensure users can only delete their own assignments
    if assignment.StudentID != current_user.StudentID:
        flash("You don't have permission to delete that.", 'danger')
        return redirect(url_for('grades_view'))

    try:
        db.session.delete(assignment)
        db.session.commit()
        flash('Assignment deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting assignment: {e}', 'danger')

    return redirect(url_for('grades_view'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
@twofa_required
def profile():
    if request.method == 'POST':
        current_user.FirstName = request.form['name'].split()[0]
        current_user.LastName = ' '.join(request.form['name'].split()[1:])
        current_user.Email = request.form['email']
        current_user.Major = request.form['major']
        current_user.Year = request.form['year']
        current_user.Units = request.form['units']
        current_user.StudentID = request.form['student_id']
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    user_data = {
        'name': f"{current_user.FirstName} {current_user.LastName}",
        'email': current_user.Email,
        'uniStudentID':  current_user.UniStudentID,
    }
    return render_template('profile.html', user=user_data)


if __name__ == '__main__':
    app.run(debug=True)
