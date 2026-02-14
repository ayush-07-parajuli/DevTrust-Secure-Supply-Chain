import sqlite3
import os

class DatabaseManager:
    def __init__(self):
        if not os.path.exists('database'): os.makedirs('database')
        db_path = os.path.join('database', 'devtrust.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                email TEXT, role TEXT, public_key TEXT, certificate TEXT, password_hash TEXT,
                PRIMARY KEY (email, role)
            )
        ''')
        # Added junior_msg column to the schema
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT, junior_id TEXT, target_reviewer_id TEXT, 
                status TEXT, signature BLOB, junior_msg TEXT, feedback TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP
            )
        ''')
        self.conn.commit()

    def get_user_by_role(self, email, role):
        self.cursor.execute("SELECT * FROM Users WHERE email=? AND role=?", (email, role))
        return self.cursor.fetchone()

    def get_reviewers(self):
        self.cursor.execute("SELECT email FROM Users WHERE role='Senior Developer'")
        return [row[0] for row in self.cursor.fetchall()]

    def add_file_record(self, file_name, junior_id, reviewer_id, signature, junior_msg, status='PENDING'):
        query = "INSERT INTO Files (file_name, junior_id, target_reviewer_id, status, signature, junior_msg, feedback) VALUES (?, ?, ?, ?, ?, ?, ?)"
        self.cursor.execute(query, (file_name, junior_id, reviewer_id, status, signature, junior_msg, ""))
        self.conn.commit()

    def get_junior_activity(self, junior_id):
        self.cursor.execute("SELECT id, file_name, target_reviewer_id, status, feedback, uploaded_at FROM Files WHERE junior_id=? ORDER BY uploaded_at DESC", (junior_id,))
        return self.cursor.fetchall()

    def get_pending_for_senior(self, senior_email):
        self.cursor.execute("SELECT id, file_name, junior_id, junior_msg, uploaded_at FROM Files WHERE target_reviewer_id=? AND status='PENDING'", (senior_email,))
        return self.cursor.fetchall()

    def get_reviewed_for_senior(self, senior_email):
        # Verification History query fix
        self.cursor.execute("SELECT id, file_name, junior_id, status, feedback FROM Files WHERE target_reviewer_id=? AND status IN ('APPROVED', 'REJECTED') ORDER BY reviewed_at DESC", (senior_email,))
        return self.cursor.fetchall()

    def update_review(self, f_id, status, feedback):
        import datetime
        self.cursor.execute("UPDATE Files SET status=?, feedback=?, reviewed_at=? WHERE id=?", (status, feedback, datetime.datetime.now(), f_id))
        self.conn.commit()

    def register_user(self, email, role, pub_key, cert, pwd):
        try:
            self.cursor.execute("INSERT INTO Users VALUES (?, ?, ?, ?, ?)", (email, role, pub_key, cert, pwd))
            self.conn.commit()
            return True
        except: return False