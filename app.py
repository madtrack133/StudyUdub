from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime

app = Flask(__name__)

# Simulated data
courses = [
    {'code': 'CITS3002'},
    {'code': 'CITS3403'},
    {'code': 'MATH1700'}
]

notes = []  # Uploaded notes
deadlines = []  # Added deadlines

# Home page
@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', courses=courses, notes=notes)

# Upload Notes page
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        title = request.form['title']
        file = request.files['file']
        category = request.form['category']
        course = request.form['course']

        notes.append({
            'title': title,
            'filename': file.filename,
            'category': category,
            'course': course,
            'date': datetime.now().strftime("%d %b %Y")
        })

        return redirect(url_for('dashboard'))

    return render_template('upload.html', courses=courses)

# Share Notes page
@app.route('/share', methods=['GET', 'POST'])
def share():
    return render_template('share.html', courses=courses)

# Shared With Me page
@app.route('/shared_with_me')
def shared_with_me():
    return render_template('shared_with_me.html', courses=courses)

# Deadlines page
@app.route('/deadlines', methods=['GET', 'POST'])
def deadlines():
    if request.method == 'POST':
        task = request.form['task']
        due_date = request.form['due_date']
        deadlines.append({'task': task, 'due_date': due_date})
        return redirect(url_for('deadlines'))
    return render_template('deadlines.html', courses=courses, deadlines=deadlines)

# View notes for a specific course
@app.route('/course/<course_code>')
def course_notes(course_code):
    filtered_notes = [note for note in notes if note['course'] == course_code]
    return render_template('course_notes.html', course=course_code, notes=filtered_notes, courses=courses)

# Add new course
@app.route('/add_course', methods=['POST'])
def add_course():
    new_course_code = request.form['course_code']
    courses.append({'code': new_course_code})
    return redirect(url_for('dashboard'))

# Rename course
@app.route('/rename_course/<old_code>', methods=['POST'])
def rename_course(old_code):
    new_code = request.form['new_code']
    for course in courses:
        if course['code'] == old_code:
            course['code'] = new_code
    return redirect(url_for('dashboard'))

# Delete course
@app.route('/delete_course/<course_code>', methods=['POST'])
def delete_course(course_code):
    global courses
    courses = [c for c in courses if c['code'] != course_code]
    return redirect(url_for('dashboard'))

# Run app
if __name__ == '__main__':
    app.run(debug=True)
