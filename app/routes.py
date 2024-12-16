from flask import Blueprint, render_template, request, redirect, url_for, session
import sqlite3
import html  # For escaping comments to mitigate XSS
from .forms import RegistrationForm
from .otp import generate_otp, verify_otp
from werkzeug.security import generate_password_hash, check_password_hash

main = Blueprint('main', __name__)

# Database helper function to prevent code duplication
def get_db_connection():
    return sqlite3.connect('normal.db')
def get_otp_secret(username):
    conn = sqlite3.connect('normal.db')
    c = conn.cursor()
    c.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)

        # Save user in DB
        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('main.login'))
        except sqlite3.IntegrityError:
            return "Username already exists", 400
    return render_template('register.html', form=form)



@main.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'username' not in session:
        return redirect(url_for('main.login'))

    otp_secret = get_otp_secret(session['username'])
    if request.method == 'POST':
        user_otp = request.form['otp']
        totp = pyotp.TOTP(otp_secret)
        if totp.verify(user_otp):
            session['authenticated'] = True
            return redirect(url_for('main.dashboard'))
        return "Invalid OTP", 401

    totp = pyotp.TOTP(otp_secret)
    print("Your OTP is:", totp.now())  # Send via email/SMS in production
    return render_template('mfa.html')

@main.route('/')
def index():
    return render_template('login.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Example database lookup
        conn = sqlite3.connect("normal.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        print(user[2], password)

        if user: #and check_password_hash(user[1], password):
            session['username'] = user[1]
            session['role'] = user[3]
            if user[3] == 'admin':
                return redirect(url_for('main.admin_dashboard', username=username))
            else:
                return redirect(url_for('main.student_dashboard', student_id=user[0], username=username))
        else:
            return "Invalid credentials", 401

    return render_template('login.html')


@main.route('/student/<int:student_id>')
def student_dashboard(student_id):
    conn = get_db_connection()
    c = conn.cursor()
    # Secure query with parameterized SQL
    c.execute("SELECT grade, comments FROM grades WHERE student_id=?", (student_id,))
    data = c.fetchone()
    conn.close()

    if 'username' not in session:
        return redirect(url_for('main.index'))  # Redirect to login if not authenticated

    username = session['username']
    if data:
        grade, comments = data
        # Escape comments to prevent XSS
        comments = html.escape(comments)
        return render_template('student_dashboard.html', username=username, grade=grade, comments=comments)
    else:
        return "No grade found", 404

@main.route('/admin/<username>', methods=['GET', 'POST'])
def admin_dashboard(username):
    if 'role' not in session or 'username' not in session:
        return redirect(url_for('main.index'))  # Redirect to login if not authenticated
    if session['role'] != 'admin':
        return "Access denied", 403  # Ensure only admins can access

    if request.method == 'POST':
        student_id = request.form['student_id']
        grade = request.form['grade']
        comments = request.form['comments']
        
        # Secure query with parameterized SQL
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE grades SET grade=?, comments=? WHERE student_id=?", (grade, comments, student_id))
        conn.commit()
        conn.close()
        return redirect(url_for('main.admin_dashboard', username=username))
    return render_template('admin_dashboard.html')

@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))
