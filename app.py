from flask import Flask, render_template, request, redirect, url_for, session
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'studyudub-secret-key'

# Home/Dashboard
@app.route('/')
@app.route('/dashboard')
def dashboard():
    courses = session.get('courses', [])
    return render_template('dashboard.html', courses=courses)

# Upload Notes (basic placeholder page)
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

# Course-specific Notes View
@app.route('/course/<course_code>')
def course_notes(course_code):
    return render_template("course_notes.html", course_code=course_code, courses=session.get('courses', []))

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
        return redirect(url_for('grades_view'))

    grades = session.get('grades', [])

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

if __name__ == '__main__':
    app.run(debug=True)
