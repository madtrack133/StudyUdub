from flask import Flask, render_template, request, redirect, url_for, session
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'studyudub-secret-key'


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


# Grades Tracker View
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

    # build summaries & chart_data as before…
    grades = session.get('grades', [])
    # … your existing summarization logic …

    return render_template(
        'grades.html',
        grades=grades,
        # pass through any summaries/chart_data you compute
        courses = session.get('courses', [])
    )


if __name__ == '__main__':
    app.run(debug=True)
