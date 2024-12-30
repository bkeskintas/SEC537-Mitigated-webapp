import os
import json
import sqlite3
from flask import Blueprint, Response, current_app, render_template, request, redirect, url_for, session, abort, flash
from werkzeug.utils import secure_filename
from datetime import datetime
import logging
import re
import requests
from werkzeug.security import check_password_hash
from functools import wraps
from . import limiter 
from . import get_remote_address
from werkzeug.security import generate_password_hash
from .forms import RegistrationForm
import socket

main = Blueprint('main', __name__)

# Configure logging for detecting intrusions and debugging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed file types for uploads
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'png'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DATABASE = 'normal.db'
REGISTER_HTML = 'register.html'
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('username'):
            abort(401)
        return f(*args, **kwargs)
    return decorated_function

def is_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'student':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def is_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def is_current_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'student_id' in kwargs and str(session.get('student_id')) != kwargs['student_id']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def is_bot(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            response_verify=request.form["g-recaptcha-response"]
            secretkey= current_app.config['RECAPTCHA_SECRET_KEY']
            verifyurl = current_app.config['VERIFY_URL']
            verify = requests.post(url=f'{verifyurl}?secret={secretkey}&response={response_verify}').json()
            #curl -X POST -F "username=testuser" -F "password=testpass" -F "g-recaptcha-response=simulate_bot" http://localhost:5000/login
            if not verify.get('success'):
                logging.error(f"Captcha verification failed from ip address: {get_remote_address}")
                abort(403, "Captcha verification failed!!")
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Check if a file is allowed based on its extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/')
@limiter.limit("10 per hour", key_func=get_remote_address)
def index():
    return render_template('login.html', captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])

@main.route('/login', methods=['POST'])
@limiter.limit("10 per hour", key_func=get_remote_address)
@is_bot
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    query = "SELECT * FROM users WHERE username=?"
    c.execute(query, (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):  # user[2] is the hashed password
        session['username'] = user[1]  # Store username in session
        session['role'] = user[3]
        session['student_id'] = user[0] # Store role in session
        logging.info(f"Login successful for user: {username}")

        if user[3] == 'admin':
            return redirect(url_for('main.admin_dashboard'))
        else:
            return redirect(url_for('main.student_dashboard', student_id=user[0]))
    else:
        logging.warning(f"Failed login attempt for username: {username}")
        return "Invalid credentials", 401

#For Identificaiton and Authentication Failures -> users can set passw like '123'
@main.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour", key_func=get_remote_address)
@is_bot
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        print("Form validated: ", form.validate_on_submit())
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template(REGISTER_HTML, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password, role, profile_photo) VALUES (?, ?, ?, ?)", (username, hashed_password, 'student', None))
                conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('main.index'))
        except sqlite3.IntegrityError:
            flash("Username already exists. Please choose another one.", "danger")
            return render_template(REGISTER_HTML, form=form, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])
        except sqlite3.OperationalError:
            flash("There was an unexpected Error. Please try again later.", "danger")
            return render_template(REGISTER_HTML, form=form, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", "danger")
        print("Form errors: ", form.errors)
    return render_template(REGISTER_HTML, form=form, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])


@main.route('/student/<student_id>')
@login_required
@is_user
@is_current_user
def student_dashboard(student_id):
    username=session['username'] 
    role=  session['role'] 
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    role = session['role']
    # Parameterized query to fetch grades for the logged-in student
    c.execute("SELECT course, grade, comments FROM grades WHERE student_id=?", (student_id,))
    courses = c.fetchall()
    c = conn.cursor()
    c.execute('SELECT profile_photo FROM users WHERE id = ?', (student_id,))

    result = c.fetchone()
    if result:
        profile_photo = result[0]
    conn.close()

    return render_template('student_dashboard.html', courses=courses, username=username, student_id=student_id, role=role, profile_photo=profile_photo)

@main.route('/student/<student_id>/grades')
@login_required
@is_user
@is_current_user
def grades(student_id):
    username = session.get('username')
    role = session.get('role')
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT course, grade, comments FROM grades WHERE student_id=?", (student_id,))
    courses = c.fetchall()
    c = conn.cursor()
    c.execute('SELECT profile_photo FROM users WHERE id = ?', (student_id,))

    result = c.fetchone()
    if result:
        profile_photo = result[0]
    conn.close()

    return render_template('grades.html', courses=courses, username=username, student_id=student_id, profile_photo=profile_photo, role=role)


@main.route('/admin')
@login_required
@is_admin
def admin_dashboard():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''SELECT u.username, g.course, g.grade, g.comments, g.id 
                 FROM grades g JOIN users u ON g.student_id = u.id''')
    grades = c.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', grades=grades)


@main.route('/admin/edit/<grade_id>', methods=['GET', 'POST'])
@login_required
@is_admin
def edit_grade(grade_id):
    conn = sqlite3.connect(DATABASE)
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

@main.route('/logout')
def logout():
    session.clear()
    logging.info("User logged out.")
    return redirect("/")

#FILE SIZE MUST BE ADDED HEREEEE
#VULNERABLE LIKE THIS
#For SSRF -> DOS Example && Software and Data Integrity Failures -> Insecure Deserialization
@main.route('/student/<student_id>/upload_assignment/<course>', methods=['GET', 'POST'])
@login_required
@is_user
@is_current_user
def upload_assignment(student_id, course):
    username = session.get('username')
    role = session.get('role')
   
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT profile_photo FROM users WHERE id = ?', (student_id,))

    result = c.fetchone()
    if result:
        profile_photo = result[0]
  
    c = conn.cursor()

    # Check if an assignment already exists for this student and course
    c.execute("SELECT file_name, file_data FROM assignments WHERE student_id=? AND course=?", (student_id, course))
    existing_assignment = c.fetchone()

    file_name = None
    deserialized_data = None
    if existing_assignment:
        file_name = existing_assignment[0]  # Existing file name
        try:
            # Secure Deserialization
            deserialized_data = json.loads(existing_assignment[1])
        except Exception as e:
            deserialized_data = f"Error deserializing data: {str(e)}"

    if request.method == 'POST':
        uploaded_file = request.files.get('file')

        # Vulnerable: No size or type validation (SSRF)
        if uploaded_file:
            # Serialize file data and store it in the database (Secure Serialization)
            serialized_data = json.dumps(uploaded_file.read().decode('latin1'))
            file_name = uploaded_file.filename
            if existing_assignment:
                # Update existing assignment
                c.execute("UPDATE assignments SET file_data=?, file_name=? WHERE student_id=? AND course=?", 
                          (serialized_data, file_name, student_id, course))
            else:
                # New assignment
                c.execute("INSERT INTO assignments (student_id, course, file_data, file_name) VALUES (?, ?, ?, ?)", 
                          (student_id, course, serialized_data, file_name))
            conn.commit()
            conn.close()
            return render_template('successfully_upload.html', 
                                   course=course, 
                                   student_id=student_id, 
                                   username=username, 
                                   role=role, profile_photo=profile_photo)

        return "No file uploaded!", 400

    conn.close()
    return render_template('upload_assignment.html', 
                           course=course, 
                           student_id=student_id, 
                           username=username, 
                           role=role, 
                           file_name=file_name, 
                           deserialized_data=deserialized_data, profile_photo=profile_photo)

@main.route('/upload_photo/<student_id>', methods=['GET', 'POST'])
@login_required
@is_current_user
def upload_photo(student_id):
    username = session.get('username')
    role = session.get('role')
    profile_photo = None

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Fetch the current profile photo
    c.execute('SELECT profile_photo FROM users WHERE id = ?', (student_id,))
    result = c.fetchone()
    if result:
        profile_photo = result[0]
    conn.close()

    if request.method == 'POST':
        photo_url = request.form.get('photo_url')
        if photo_url:
            # Validate the URL before making a request
            if not photo_url.lower().startswith(('http://', 'https://')):
                flash('Invalid!')
                return redirect(url_for('main.upload_photo', student_id=student_id))

            # Basic regex validation for suspicious domains (you can add more checks)
            url_regex = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
            if not re.match(url_regex, photo_url):
                flash('Invalid!')
                return redirect(url_for('main.upload_photo', student_id=student_id))

            # Perform a DNS resolution check to ensure the domain is legitimate
            try:
                domain = photo_url.split('/')[2]  # Extract domain from URL
                ip_address = socket.gethostbyname(domain)  # DNS resolution

                # Check for private IP addresses
                if ip_address.startswith("127.") or ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("169.254."):
                    flash('Invalid!')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

            except socket.gaierror:
                flash('Failed to resolve the domain. URL might be invalid!')
                return redirect(url_for('main.upload_photo', student_id=student_id))

            try:
                # Fetch the image data with a shorter timeout
                response = requests.get(photo_url, timeout=5)
                response.raise_for_status()  # Raise an HTTPError for bad responses

                # Check if the response is an image and validate its type using magic bytes
                if 'image' not in response.headers.get('Content-Type', ''):
                    flash('The URL does not point to an image!')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

                file_data = response.content  # Binary content of the image

                # Validate image type using magic bytes
                if not (file_data.startswith(b'\xff\xd8') or file_data.startswith(b'\x89PNG\r\n\x1a\n')):
                    flash('The URL does not point to a valid JPEG or PNG image!')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

                # Store the image in the database
                conn = sqlite3.connect(DATABASE)
                c = conn.cursor()
                c.execute('UPDATE users SET profile_photo = ? WHERE id = ?', (file_data, student_id))
                conn.commit()
                conn.close()

                flash('Profile photo uploaded successfully!')
                return redirect(url_for('main.upload_photo', student_id=student_id))

            except requests.exceptions.Timeout:
                flash('The request timed out. Please provide a faster URL.')
                return redirect(url_for('main.upload_photo', student_id=student_id))

            except requests.exceptions.RequestException as e:
                flash(f'Failed to fetch the photo from the URL: {str(e)}')
                return redirect(url_for('main.upload_photo', student_id=student_id))

        flash('No photo URL provided!')
        return redirect(url_for('main.upload_photo', student_id=student_id))

    return render_template('upload_photo.html', username=username, role=role, student_id=student_id, profile_photo=profile_photo)

@main.route('/get_profile_photo/<student_id>')
@login_required
@is_current_user
def get_profile_photo(student_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Fetch the profile photo from the database
    c.execute('SELECT profile_photo FROM users WHERE id = ?', (student_id,))
    result = c.fetchone()
    conn.close()

    if result and result[0]:
        # Return the binary data as an image
        return Response(result[0], mimetype='image/jpeg')
    else:
        # Return a default image if no profile photo is found
        return redirect(url_for('static', filename='user.png'))

