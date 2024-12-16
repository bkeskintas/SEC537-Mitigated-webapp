import sqlite3
import pyotp

def init_db():
    conn = sqlite3.connect('normal.db')
    c = conn.cursor()

    # Create the 'users' table with an 'otp_secret' column for MFA
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        otp_secret TEXT NOT NULL
    )''')

    # Create the 'grades' table
    c.execute('''CREATE TABLE IF NOT EXISTS grades (
        student_id INTEGER,
        grade TEXT,
        comments TEXT
    )''')

    # Generate OTP secret keys for users
    admin_otp = pyotp.random_base32()
    duygu_otp = pyotp.random_base32()
    burak_otp = pyotp.random_base32()

    # Insert users with OTP secret keys
    try:
        c.execute("INSERT INTO users (username, password, role, otp_secret) VALUES (?, ?, ?, ?)", 
                  ('admin', 'admin123', 'admin', admin_otp))
        c.execute("INSERT INTO users (username, password, role, otp_secret) VALUES (?, ?, ?, ?)", 
                  ('duygu', 'duygu123', 'student', duygu_otp))
        c.execute("INSERT INTO users (username, password, role, otp_secret) VALUES (?, ?, ?, ?)", 
                  ('burak', 'burak123', 'student', burak_otp))
    except sqlite3.IntegrityError:
        print("Users already exist in the database.")

    # Insert sample grades data
    c.execute("INSERT OR IGNORE INTO grades (student_id, grade, comments) VALUES (?, ?, ?)", (1, 'A', 'Great job!'))
    c.execute("INSERT OR IGNORE INTO grades (student_id, grade, comments) VALUES (?, ?, ?)", (2, 'A', 'Excellent work!'))
    c.execute("INSERT OR IGNORE INTO grades (student_id, grade, comments) VALUES (?, ?, ?)", (3, 'B', 'Needs improvement'))

    conn.commit()
    conn.close()

    # Print OTP secrets for testing purposes (remove this in production)
    print("User OTP Secrets (For Testing):")
    print(f"Admin OTP Secret: {admin_otp}")
    print(f"Duygu OTP Secret: {duygu_otp}")
    print(f"Burak OTP Secret: {burak_otp}")

# Run the function to initialize the database
if __name__ == "__main__":
    init_db()
