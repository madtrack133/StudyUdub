from flask import Flask, render_template, request, redirect, url_for, session
from collections import defaultdict

app = Flask(__name__)
app.config.from_object(Config)

# Ensure SECRET_KEY is set
if not app.config.get('SECRET_KEY'):
    app.config['SECRET_KEY'] = 'studyudub-fallback-secret'

app.secret_key = app.config['SECRET_KEY']

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


# ─── AUTH ROUTES ───────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        # In a real app you'd validate against a user database here
        session['user'] = {'username': username}
        return redirect(url_for('dashboard'))
    return render_template('login.html', courses=session.get('courses', []))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Here you would create the user record in your database
        return redirect(url_for('login'))
    return render_template('signup.html', courses=session.get('courses', []))


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('dashboard'))


@app.route('/profile')
def profile():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    return render_template('profile.html', user=user, courses=session.get('courses', []))


# ─── MAIN APP ROUTES ────────────────────────────────────────────────────────────

# Home/Dashboard
@app.route('/')
@app.route('/dashboard')
def dashboard():
    courses = session.get('courses', [])
    user = session.get('user')
    return render_template('dashboard.html', courses=courses, user=user)


# Upload Notes
@app.route('/upload')
def upload():
    return render_template('upload.html', courses=session.get('courses', []))


# Share Notes
@app.route('/share')
def share():
    return render_template('share.html', courses=session.get('courses', []))


# Shared With Me
@app.route('/shared_with_me')
def shared_with_me():
    return render_template('shared_with_me.html', courses=session.get('courses', []))


# Deadlines
@app.route('/deadlines')
def deadlines():
    return render_template('deadlines.html', courses=session.get('courses', []))


# Course Notes
@app.route('/course/<course_code>')
def course_notes(course_code):
    return render_template(
        'course_notes.html',
        course_code=course_code,
        courses=session.get('courses', [])
    )


# Add a New Course
@app.route('/add_course', methods=['POST'])
def add_course():
    course_code = request.form['course_code']
    if 'courses' not in session:
        session['courses'] = []
    if not any(c['code'] == course_code for c in session['courses']):
        session['courses'].append({'code': course_code})
    session.modified = True
    return redirect(url_for('dashboard'))


@login_required
@twofa_required

@app.route('/grades', methods=['GET', 'POST'])
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

        return redirect(url_for('grades_view'))

    grades = session.get('grades', [])

    from collections import defaultdict
    summaries = defaultdict(lambda: {'achieved': 0, 'assessments': []})
    chart_data = {}

    for grade in grades:
        unit = grade['unit']
        summaries[unit]['achieved'] += grade['contribution']
        summaries[unit]['assessments'].append({
            'assessment': grade['assessment'],
            'contribution': grade['contribution']
        })

    for unit, data in summaries.items():
        chart_data[unit] = {
            'labels': [a['assessment'] for a in data['assessments']],
            'values': [a['contribution'] for a in data['assessments']]
        }
        data['remaining'] = round(max(0, 50 - data['achieved']), 1)
        data['achieved'] = round(data['achieved'], 1)

    return render_template(
        'grades.html',
        grades=grades,

        summaries=summaries,
        chart_data=chart_data,
        courses=session.get('courses', [])
    )


@app.route("/profile", methods=["GET"])
def profile():
    user = session.get('user', {
        "name": "Ray Hale",
        "email": "rayhale@example.com",
        "student_id": "12345678",
        "major": "Computer Science",
        "year": "3rd Year",
        "units": "MATH1700, CITS3403, CITS3002"
    })
    return render_template("profile.html", user=user)

@app.route("/update_profile", methods=["POST"])
def update_profile():
    user = {
        "name": request.form["name"],
        "email": request.form["email"],
        "student_id": request.form["student_id"],
        "major": request.form["major"],
        "year": request.form["year"],
        "units": request.form["units"]
    }
    session['user'] = user  # Store in session for now
    return redirect(url_for("profile"))

>>>>>>> Stashed changes

if __name__ == '__main__':
    app.run(debug=True)
