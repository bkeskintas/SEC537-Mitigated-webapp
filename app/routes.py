import os
import sqlite3
from flask import Blueprint, current_app, render_template, request, redirect, url_for, session, abort
from werkzeug.utils import secure_filename
from datetime import datetime
import logging
import requests
from werkzeug.security import check_password_hash

main = Blueprint('main', __name__)

# Configure logging for detecting intrusions and debugging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed file types for uploads
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'png'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def allowed_file(filename):
    """Check if a file is allowed based on its extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@main.route('/')
def index():
    return render_template('login.html')


@main.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('normal.db')
    c = conn.cursor()
    query = "SELECT * FROM users WHERE username=?"
    c.execute(query, (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):  # user[2] is the hashed password
        session['username'] = user[1]  # Store username in session
        session['role'] = user[3]      # Store role in session
        logging.info(f"Login successful for user: {username}")

        if user[3] == 'admin':
            return redirect(url_for('main.admin_dashboard'))
        else:
            return redirect(url_for('main.student_dashboard', student_id=user[0]))
    else:
        logging.warning(f"Failed login attempt for username: {username}")
        return "Invalid credentials", 401


@main.route('/student/<student_id>')
def student_dashboard(student_id):
    if not session.get('username') or session.get('role') != 'student':
        abort(403)

    conn = sqlite3.connect('normal.db')
    c = conn.cursor()
    # Parameterized query to fetch grades for the logged-in student
    c.execute("SELECT course, grade, comments FROM grades WHERE student_id=?", (student_id,))
    courses = c.fetchall()
    conn.close()

    return render_template('student_dashboard.html', courses=courses, username=session['username'], student_id=student_id)


@main.route('/student/<student_id>/grades')
def grades(student_id):
    if not session.get('username') or session.get('role') != 'student':
        abort(403)

    conn = sqlite3.connect('normal.db')
    c = conn.cursor()
    c.execute("SELECT course, grade, comments FROM grades WHERE student_id=?", (student_id,))
    courses = c.fetchall()
    conn.close()

    return render_template('grades.html', courses=courses, username=session['username'], student_id=student_id)


@main.route('/admin')
def admin_dashboard():
    if not session.get('username') or session.get('role') != 'admin':
        abort(403)

    conn = sqlite3.connect('normal.db')
    c = conn.cursor()
    c.execute('''SELECT u.username, g.course, g.grade, g.comments, g.id 
                 FROM grades g JOIN users u ON g.student_id = u.id''')
    grades = c.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', grades=grades)


@main.route('/admin/edit/<grade_id>', methods=['GET', 'POST'])
def edit_grade(grade_id):
    if not session.get('username') or session.get('role') != 'admin':
        abort(403)

    conn = sqlite3.connect('normal.db')
    c = conn.cursor()

    if request.method == 'POST':
        grade = request.form['grade']
        comments = request.form['comments']

        c.execute("UPDATE grades SET grade=?, comments=? WHERE id=?", (grade, comments, grade_id))
        conn.commit()
        conn.close()
        logging.info(f"Grade updated for grade_id: {grade_id} by admin: {session['username']}")
        return redirect(url_for('main.admin_dashboard'))
    
    c.execute("SELECT course, grade, comments FROM grades WHERE id=?", (grade_id,))
    grade_data = c.fetchone()
    conn.close()
    return render_template('edit_grade.html', grade_data=grade_data)


@main.route('/student/<student_id>/upload_resource', methods=['GET', 'POST'])
def upload_resource(student_id):
    if not session.get('username') or session.get('role') != 'student':
        abort(403)

    if request.method == 'POST':
        url = request.form.get('url')

        try:
            parsed_url = requests.utils.urlparse(url)
            if parsed_url.netloc not in ['trusted-resource.com']:
                raise ValueError("Untrusted domain")

            response = requests.get(url, timeout=5)
            content_type = response.headers.get('Content-Type', '')

            if 'text/html' in content_type:
                content = response.text
            else:
                content = "Unsupported file type."

        except Exception as e:
            logging.error(f"SSRF attempt or error: {str(e)}")
            content = f"Error fetching resource: {str(e)}"

        return render_template('upload_resource.html', url=url, content=content, student_id=student_id)

    return render_template('upload_resource.html', student_id=student_id)


@main.route('/logout')
def logout():
    session.clear()
    logging.info(f"User logged out.")
    return redirect("/")


@main.route('/student/<student_id>/upload', methods=['GET', 'POST'])
def upload_file(student_id):
    if not session.get('username') or session.get('role') != 'student':
        abort(403)

    if request.method == 'POST':
        uploaded_file = request.files.get('file')

        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)

            if uploaded_file.content_length > MAX_FILE_SIZE:
                return "File size exceeds the limit!", 413

            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(file_path)
            logging.info(f"File uploaded: {filename} by student_id: {student_id}")
            return f"File uploaded successfully: {filename}"

        return "Invalid file type or no file uploaded!", 400

    return render_template('upload_project.html', student_id=student_id)
