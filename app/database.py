import sqlite3

def init_db():
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    # Recreate the grades table with a comments column
    c.execute('''CREATE TABLE IF NOT EXISTS grades (
        student_id INTEGER,
        grade TEXT,
        comments TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT
    )''')
    
    c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    c.execute("INSERT INTO users (username, password, role) VALUES ('duygu', 'duygu123', 'student')")
    c.execute("INSERT INTO users (username, password, role) VALUES ('burak', 'burak123', 'student')")
    c.execute("INSERT INTO grades (student_id, grade, comments) VALUES (1, 'A', 'Great job!')")
    c.execute("INSERT INTO grades (student_id, grade, comments) VALUES (2, 'A', 'Great job!')")
    c.execute("INSERT INTO grades (student_id, grade, comments) VALUES (3, 'B', 'Needs improvement')")
    conn.commit()
    conn.close()
