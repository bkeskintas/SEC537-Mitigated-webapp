from flask import Blueprint, render_template, request, redirect, url_for, session
import sqlite3
import html  # For escaping comments to mitigate XSS

main = Blueprint('main', __name__)

# Database helper function to prevent code duplication
def get_db_connection():
    return sqlite3.connect('normal.db')

@main.route('/')
def index():
    return render_template('login.html')

@main.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Secure SQL query using parameterized query
    query = "SELECT * FROM users WHERE username=? AND password=?"
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(query, (username, password))  # Parameterized query
    user = c.fetchone()
    conn.close()
    
    if user:
        session['username'] = user[1]
        session['role'] = user[3]
        if user[3] == 'admin':
            return redirect(url_for('main.admin_dashboard', username=username))
        else:
            return redirect(url_for('main.student_dashboard', student_id=user[0], username=username))
    else:
        return "Invalid credentials", 401

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
