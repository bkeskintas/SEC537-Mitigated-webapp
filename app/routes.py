from flask import Blueprint, render_template, request, redirect, url_for, session

import sqlite3

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('login.html')

@main.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Vulnerable SQL Query (SQL Injection)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute(query)  # No parameterized query
    user = c.fetchone()
    conn.close()
    
    if user:
        role = user[3]
        session['username'] = user[1]  # Store username in session
        session['role'] = user[3]      # Store role in session
        if user[3] == 'admin':
            return redirect(url_for('main.admin_dashboard', username=username))
        else:
            return redirect(url_for('main.student_dashboard', student_id=user[0], username=username))
    else:
        return "Invalid credentials"



@main.route('/student/<student_id>')
def student_dashboard(student_id):
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute(f"SELECT grade, comments FROM grades WHERE student_id={student_id}")
    data = c.fetchone()
    conn.close()
    username = session['username']
    if data:
        grade, comments = data
        # Reflect comments directly (vulnerable to XSS)
        return render_template('grades.html', username=username, grade=grade, comments=comments)
    else:
        return "No grade found", 404



@main.route('/admin/<username>', methods=['GET', 'POST'])
def admin_dashboard(username):
    # Check if the user is logged in and has a role
    if 'role' not in session or 'username' not in session:
        return redirect(url_for('main.index'))  # Redirect to login if not authenticated

    

    # If the method is POST, update the grades
    if request.method == 'POST':
        student_id = request.form['student_id']
        grade = request.form['grade']
        comments = request.form['comments'].replace("'", "''")  # Escape single quotes
        
        # Update the database (vulnerable query for testing purposes)
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        c.execute(f"UPDATE grades SET grade='{grade}', comments='{comments}' WHERE student_id={student_id}")
        conn.commit()
        conn.close()
        return redirect(url_for('main.admin_dashboard', username=username))
    return render_template('admin_dashboard.html')




        


