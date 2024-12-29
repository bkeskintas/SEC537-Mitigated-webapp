import sqlite3
from werkzeug.security import generate_password_hash
import logging

logging.basicConfig(filename='db_operations.log', level=logging.INFO)

def init_db():
    conn = sqlite3.connect('normal.db') 
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'student'))
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS grades (
        id INTEGER PRIMARY KEY,
        student_id INTEGER NOT NULL,
        course TEXT NOT NULL,
        grade TEXT CHECK(grade IN ('A', 'B', 'C', 'D', 'F')),
        comments TEXT,
        FOREIGN KEY(student_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,                
        student_id INTEGER NOT NULL,                         
        course TEXT NOT NULL CHECK(course <> ''),            
        file_data BLOB NOT NULL,                             
        file_name TEXT NOT NULL CHECK(file_name <> ''),      
        FOREIGN KEY(student_id) REFERENCES users(id)      
    )''')

    #check if users table is empty,  if not it won't do this
    c.execute('SELECT COUNT(*) FROM users')
    encrypt_method = 'pbkdf2:sha256'
    if c.fetchone()[0] == 0:  #only insert if the table is empty
        users = [
            ('admin', generate_password_hash('Az09.IamAmin', method=encrypt_method), 'admin'),
            ('duygu', generate_password_hash('Az09.IamDuygu', method=encrypt_method), 'student'),
            ('burak', generate_password_hash('Az09.IamBurak', method=encrypt_method), 'student')
        ]
        for user in users:
            c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', user)
            logging.info(f"Inserted user: {user[0]}")

    #check if grades table is empty, if not it won't do this
    c.execute('SELECT COUNT(*) FROM grades')
    if c.fetchone()[0] == 0:  #only insert if the table is empty
        grades = [
            (2, 'Human Computer Interaction', 'A', 'Outstanding'),
            (2, 'Cybersecurity Practices and App.', 'A', 'Great job!'),
            (2, 'Fundamentals of Computing', 'A', 'Outstanding'),
            (2, 'Math', 'A', 'Great job!'),
            (2, 'Physics', 'A', 'Outstanding'),
            (3, 'Math', 'C', 'Needs improvement'),
            (3, 'Chemistry', 'B', 'Good progress')
        ]
        for grade in grades:
            c.execute('INSERT INTO grades (student_id, course, grade, comments) VALUES (?, ?, ?, ?)', grade)
            logging.info(f"Inserted grade for student_id {grade[0]} in course {grade[1]}")

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
