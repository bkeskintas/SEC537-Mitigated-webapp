import json
import os
import sqlite3
import bcrypt
from flask import Blueprint, Response, current_app, render_template, request, redirect, url_for, session, abort, flash
import logging
import re
import requests
from werkzeug.security import check_password_hash
from functools import wraps
from . import limiter 
from . import get_remote_address
from .forms import RegistrationForm
import socket
import magic
from werkzeug.utils import secure_filename
from jinja2.utils import urlize
from time import perf_counter

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
            try:
                response_verify=request.form["g-recaptcha-response"]
                secretkey= current_app.config['RECAPTCHA_SECRET_KEY']
                verifyurl = current_app.config['VERIFY_URL']
                verify = requests.post(url=f'{verifyurl}?secret={secretkey}&response={response_verify}').json()
                #curl -X POST -F "username=testuser" -F "password=testpass" -F "g-recaptcha-response=simulate_bot" http://localhost:5000/login
                if not verify.get('success'):
                    logging.error(f"Captcha verification failed from ip address: {get_remote_address}")
                    abort(403, "Captcha verification failed!!")
            except Exception as e:
                logging.error(f"Captcha verification failed from ip address: {get_remote_address}. Server error: {e}")
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
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    #validate the username format (alphanumeric, underscores, or dashes, 3-20 characters)
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        logging.warning(f"Invalid username format attempted: {username}")
        return "Invalid username or password", 401

    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        query = "SELECT id, username, password, role FROM users WHERE username=?"
        c.execute(query, (username,))
        user = c.fetchone()
    finally:
        conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):  # user[2] is the hashed password
        session['username'] = user[1]  
        session['role'] = user[3]
        session['student_id'] = user[0]  

        logging.info("Login successful for user: %s", username)

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
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        #allow only alphanumeric and limited special characters for username
        if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
            flash("Username contains invalid characters. Use only letters, numbers, and _.-", "danger")
            return render_template(REGISTER_HTML, form=form, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])

        #validate password strength
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
            flash("Password must be at least 8 characters long and include an uppercase letter and a number.", "danger")
            return render_template(REGISTER_HTML, form=form, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template(REGISTER_HTML, form=form, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        except Exception as e:
            logging.error(f"Error during password hashing: {e}")
            flash("An error occurred. Please try again later.", "danger")
            return render_template(REGISTER_HTML, form=form, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])

        try:
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                # Insert new user into the database
                c.execute("INSERT INTO users (username, password, role, profile_photo) VALUES (?, ?, ?, ?)",
                          (username, hashed_password, 'student', None))
                conn.commit()
                logging.info(f"New user registered: {username}")
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('main.index'))
        except sqlite3.IntegrityError:
            logging.warning(f"Username already exists: {username}")
            flash("Username already exists. Please choose another one.", "danger")
        except sqlite3.OperationalError as e:
            logging.error(f"Database error during registration: {e}")
            flash("An unexpected error occurred. Please try again later.", "danger")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", "danger")
    return render_template(REGISTER_HTML, form=form, captchaKey=current_app.config['RECAPTCHA_SITE_KEY'])


@main.route('/student/<student_id>')
@login_required
@is_user
@is_current_user
def student_dashboard(student_id):
    try:
        student_id = int(student_id)
        
        username = session['username']
        role = session['role']

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        c.execute("SELECT course, grade, comments FROM grades WHERE student_id=?", (student_id,))
        courses =  c.fetchall()

        c.execute("SELECT profile_photo FROM users WHERE id=?", (student_id,))
        result = c.fetchone()
        profile_photo = result[0] if result else None

    except ValueError:
        abort(400)  #invalid student_id format
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        flash("An error occurred while fetching your data. Please try again later.", "danger")
        return redirect(url_for('main.index'))
    finally:
        conn.close()

    return render_template(
        'student_dashboard.html',
        courses=courses,
        username=username,
        student_id=student_id,
        role=role,
        profile_photo=profile_photo
    )

@main.route('/student/<student_id>/grades')
@login_required
@is_user
@is_current_user
def grades(student_id):
    username = session.get('username')
    role = session.get('role')

    try:
        student_id = int(student_id)

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        query = "SELECT course, grade, comments FROM grades WHERE student_id=?"
        c.execute(query, (student_id,))
        courses = c.fetchall()

        c.execute("SELECT profile_photo FROM users WHERE id=?", (student_id,))
        result = c.fetchone()
        profile_photo = result[0] if result else None

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        flash("An error occurred while fetching grades. Please try again later.", "danger")
        return redirect(url_for('main.index'))
    finally:
        conn.close()

    return render_template(
        'grades.html', 
        courses=courses, 
        username=username, 
        student_id=student_id, 
        profile_photo=profile_photo, 
        role=role
    )


@main.route('/admin')
@login_required
@is_admin
def admin_dashboard():
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        query = '''
            SELECT u.username, g.course, g.grade, g.comments, g.id 
            FROM grades g 
            JOIN users u ON g.student_id = u.id
            LIMIT ? OFFSET ?
        '''
        page = request.args.get('page', 1, type=int)
        limit = 10  # Number of records per page
        offset = (page - 1) * limit
        c.execute(query, (limit, offset))
        grades = c.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        flash("An error occurred while fetching grades. Please try again later.", "danger")
        return redirect(url_for('main.index'))
    finally:
        if conn:
            conn.close()

    logging.info(f"Admin {session['username']} accessed the admin dashboard.")
    return render_template('admin_dashboard.html', grades=grades)

@main.route('/admin/edit/<grade_id>', methods=['GET', 'POST'])
@login_required
@is_admin
def edit_grade(grade_id):
    try:
        grade_id = int(grade_id)
    except ValueError:
        abort(400)  #Bad Request

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    if request.method == 'POST':
        grade = request.form.get('grade', '').strip()
        comments = request.form.get('comments', '').strip()

        if grade not in ['A', 'B', 'C', 'D', 'F']:
            flash("Invalid grade!", "danger")
            return redirect(url_for('main.edit_grade', grade_id=grade_id))

        if not comments:
            flash("Comments cannot be empty!", "danger")
            return redirect(url_for('main.edit_grade', grade_id=grade_id))

        c.execute("SELECT grade, comments FROM grades WHERE id=?", (grade_id,))
        original_data = c.fetchone()

        c.execute("UPDATE grades SET grade=?, comments=? WHERE id=?", (grade, comments, grade_id))
        conn.commit()
        conn.close()

        logging.info(f"Admin {session['username']} updated grade ID {grade_id}. Original data: {original_data}. New data: Grade={grade}, Comments={comments}.")
        flash("Grade updated successfully!", "success")
        return redirect(url_for('main.admin_dashboard'))

    c.execute("SELECT course, grade, comments FROM grades WHERE id=?", (grade_id,))
    grade_data = c.fetchone()
    conn.close()

    if not grade_data:
        flash("Grade not found!", "danger")
        return redirect(url_for('main.admin_dashboard'))

    return render_template('edit_grade.html', grade_data=grade_data)


@main.route('/logout', methods=['POST'])
def logout():
    session.clear()
    logging.info("User logged out.")
    flash("You have been logged out successfully.", "info")
    return redirect("/")

@main.route('/lol')
def lol_route():
   for i in range(3):
        text = "abc@" + "." * (i+1)*5000 + "!"
   lenValue = len(text)
   begin = perf_counter()
   urlize(text)
   DURATION = perf_counter() - begin
   return f"Result: {DURATION}"

@main.route('/student/<student_id>/upload_assignment/<course>', methods=['GET', 'POST'])
@login_required
@is_user
@is_current_user
@limiter.limit("5 per minute", key_func=get_remote_address)
def upload_assignment(student_id, course):
    username = session.get('username')
    role = session.get('role')
    profile_photo = None

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    #fetch the current profile photo
    c.execute('SELECT profile_photo FROM users WHERE id = ?', (student_id,))
    result = c.fetchone()
    if result:
        profile_photo = result[0]

    #check if an assignment already exists for this student and course
    c.execute("SELECT file_name, file_data FROM assignments WHERE student_id=? AND course=?", (student_id, course))
    existing_assignment = c.fetchone()

    file_name = None
    deserialized_data = None
    if existing_assignment:
        file_name = existing_assignment[0]  # Existing file name
        try:
            #secure Deserialization
            deserialized_data = json.loads(existing_assignment[1])
        except json.JSONDecodeError:
            logging.error("Deserialization failed for student_id: %s, course: %s", student_id, course)
            deserialized_data = None  #handle securely without exposing errors

    if request.method == 'POST':
        uploaded_file = request.files.get('file')

        if uploaded_file:
            #ensure the file has an allowed extension
            file_extension = uploaded_file.filename.rsplit('.', 1)[1].lower() if '.' in uploaded_file.filename else ''
            if file_extension not in ALLOWED_EXTENSIONS:
                flash('Invalid file type. Only PDF, DOCX and PNG are allowed!', 'warning')
                return redirect(url_for('main.upload_assignment', student_id=student_id, course=course))

            #validate file size
            uploaded_file.seek(0, os.SEEK_END)  #move to end of file
            file_size = uploaded_file.tell()  #get file size
            uploaded_file.seek(0)  #reset file pointer to the beginning
            if file_size > MAX_FILE_SIZE:
                flash('File size exceeds the 10 MB limit!', 'warning')
                return redirect(url_for('main.upload_assignment', student_id=student_id, course=course))

            #validate MIME type using python-magic
            mime = magic.Magic(mime=True)
            mime_type = mime.from_buffer(uploaded_file.read(2048))  #read the first 2 KB for MIME validation
            uploaded_file.seek(0)  #reset file pointer
            if mime_type not in {'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}:
                flash('Invalid file type. Only PDF and DOCX are allowed!', 'warning')
                return redirect(url_for('main.upload_assignment', student_id=student_id, course=course))

            #serrialize file data securely
            serialized_data = json.dumps(uploaded_file.read().decode('latin1'))  #Using safe serialization
            file_name = secure_filename(uploaded_file.filename)  #prevent directory traversal attacks

            #insert or update assignment
            try:
                if existing_assignment:
                    c.execute("UPDATE assignments SET file_data=?, file_name=? WHERE student_id=? AND course=?", 
                              (serialized_data, file_name, student_id, course))
                else:
                    c.execute("INSERT INTO assignments (student_id, course, file_data, file_name) VALUES (?, ?, ?, ?)", 
                              (student_id, course, serialized_data, file_name))
                conn.commit()
                flash('Assignment uploaded successfully!', 'success')
                render_template('successfully_upload.html', 
                                   course=course, 
                                   student_id=student_id, 
                                   username=username, 
                                   role=role, profile_photo=profile_photo)
            except sqlite3.Error as e:
                logging.error("Database error during assignment upload: %s", str(e))
                flash('An error occurred while uploading the assignment. Please try again later.', 'warning')
            finally:
                conn.close()

            return redirect(url_for('main.upload_assignment', student_id=student_id, course=course))

        flash('No file uploaded!')
        return redirect(url_for('main.upload_assignment', student_id=student_id, course=course))

    conn.close()
    return render_template('upload_assignment.html', 
                           course=course, 
                           student_id=student_id, 
                           username=username, 
                           role=role, 
                           file_name=file_name, 
                           deserialized_data=deserialized_data, 
                           profile_photo=profile_photo)


@main.route('/upload_photo/<student_id>', methods=['GET', 'POST'])
@login_required
@is_current_user
@limiter.limit("5 per minute", key_func=get_remote_address)  #rate limiting
def upload_photo(student_id):
    username = session.get('username')
    role = session.get('role')
    profile_photo = None

    WHITELISTED_DOMAINS = ['i.pinimg.com', 'i.imgur.com', 'images.unsplash.com']
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    #fetch the current profile photo
    c.execute('SELECT profile_photo FROM users WHERE id = ?', (student_id,))
    result = c.fetchone()
    if result:
        profile_photo = result[0]
    conn.close()

    if request.method == 'POST':
        photo_url = request.form.get('photo_url')
        if photo_url:
            try:
                #validate the URL before making a request
                if not photo_url.lower().startswith(('http://', 'https://')):
                    flash('Invalid URL! Only HTTP/HTTPS URLs are allowed.')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

                
                domain = photo_url.split('/')[2] #get domain 
                if domain not in WHITELISTED_DOMAINS:
                    flash('URL is not from a trusted domain.')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

                #perform DNS resolution and check for private IPs
                try:
                    ip_address = socket.gethostbyname(domain) # DNS resolution
                    if ip_address.startswith(("127.", "192.168.", "10.")):
                        flash('URL points to a private network address. Not allowed!')
                        return redirect(url_for('main.upload_photo', student_id=student_id))
                except socket.gaierror:
                    flash('Failed to resolve the domain. URL might be invalid.')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

                #fetch the image data with a stricter timeout
                response = requests.get(photo_url, timeout=2) 
                response.raise_for_status()

                #check if the response is an image
                if 'image' not in response.headers.get('Content-Type', ''):
                    flash('The URL does not point to an image!')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

                file_data = response.content

                #validate image type using robust library (python-magic)
                mime = magic.Magic(mime=True)
                file_type = mime.from_buffer(file_data)
                if file_type not in ['image/jpeg', 'image/png']:
                    flash('Invalid image type! Only JPEG and PNG are allowed.')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

                #limit the file size to prevent DoS
                if len(file_data) > 2 * 1024 * 1024:  # 2 MB limit
                    flash('Image size exceeds the 2 MB limit.')
                    return redirect(url_for('main.upload_photo', student_id=student_id))

                #store the image in the database
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

            except requests.exceptions.RequestException:
                flash('Failed to fetch the photo from the URL.')
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

    c.execute('SELECT profile_photo FROM users WHERE id = ?', (student_id,))
    result = c.fetchone()
    conn.close()

    if result and result[0]:
        # Return the binary data as an image
        return Response(result[0], mimetype='image/jpeg')
    else:
        return redirect(url_for('static', filename='user.png'))
