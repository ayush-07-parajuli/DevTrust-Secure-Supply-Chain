import sqlite3
import os
import datetime


class DatabaseManager:
    def __init__(self):
        if not os.path.exists("database"):
            os.makedirs("database")

        db_path = os.path.join("database", "devtrust.db")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()

        # Enable foreign keys (safe even if not used heavily yet)
        self.cursor.execute("PRAGMA foreign_keys = ON;")
        self.conn.commit()

        self.create_tables()

    def create_tables(self):
        # Users table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                email TEXT,
                role TEXT,
                public_key TEXT,
                certificate TEXT,
                password_hash TEXT,
                PRIMARY KEY (email, role)
            )
        """)

        # Files table (includes signature + hash + junior_msg)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS Files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT,
                junior_id TEXT,
                target_reviewer_id TEXT,
                status TEXT,
                signature BLOB,
                file_hash TEXT,
                junior_msg TEXT,
                feedback TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP
            )
        """)

        # ✅ Audit logs table (Commit 4)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS AuditLogs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                user_role TEXT,
                action TEXT,
                details TEXT,
                file_id INTEGER,
                file_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        self.conn.commit()

        # Backward compatible migration if older DB exists
        self._ensure_column("Files", "file_hash", "TEXT")
        self._ensure_column("Files", "junior_msg", "TEXT")
        self._ensure_column("Users", "password_hash", "TEXT")

    def _ensure_column(self, table_name, column_name, column_type):
        try:
            self.cursor.execute(f"PRAGMA table_info({table_name})")
            cols = [row[1] for row in self.cursor.fetchall()]
            if column_name not in cols:
                self.cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                self.conn.commit()
        except:
            pass

    # Audit logging API
    def log_event(self, user_email, user_role, action, details=None, file_id=None, file_name=None):
        try:
            self.cursor.execute("""
                INSERT INTO AuditLogs (user_email, user_role, action, details, file_id, file_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_email, user_role, action, details, file_id, file_name))
            self.conn.commit()
        except:
            # Logging should never crash the app
            pass

    def get_audit_logs(self, limit=200):
        self.cursor.execute("""
            SELECT id, user_email, user_role, action, details, file_id, file_name, created_at
            FROM AuditLogs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        return self.cursor.fetchall()

    # -------------------------
    # Existing project methods
    # -------------------------

    def register_user(self, email, role, pub_key, cert, pwd_hash):
        try:
            self.cursor.execute("""
                INSERT INTO Users (email, role, public_key, certificate, password_hash)
                VALUES (?, ?, ?, ?, ?)
            """, (email, role, pub_key, cert, pwd_hash))
            self.conn.commit()
            return True
        except:
            return False

    def get_user_by_role(self, email, role):
        self.cursor.execute("SELECT * FROM Users WHERE email=? AND role=?", (email, role))
        return self.cursor.fetchone()

    def get_public_key(self, email, role="Junior Developer"):
        self.cursor.execute("SELECT public_key FROM Users WHERE email=? AND role=?", (email, role))
        r = self.cursor.fetchone()
        return r[0] if r else None

    def get_reviewers(self):
        self.cursor.execute("SELECT email FROM Users WHERE role='Senior Developer'")
        return [r[0] for r in self.cursor.fetchall()]

    # now stores file_hash too
    def add_file_record(self, file_name, junior_id, reviewer_id, signature, file_hash, junior_msg, status="PENDING"):
        self.cursor.execute("""
            INSERT INTO Files (file_name, junior_id, target_reviewer_id, status, signature, file_hash, junior_msg, feedback)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            file_name,
            junior_id,
            reviewer_id,
            status,
            sqlite3.Binary(signature) if signature is not None else None,
            file_hash,
            junior_msg,
            ""
        ))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_junior_activity(self, junior_email):
        self.cursor.execute("""
            SELECT id, file_name, target_reviewer_id, status, feedback, uploaded_at
            FROM Files
            WHERE junior_id=?
            ORDER BY id DESC
        """, (junior_email,))
        return self.cursor.fetchall()

    def get_pending_for_senior(self, senior_email):
        self.cursor.execute("""
            SELECT id, file_name, junior_id, junior_msg
            FROM Files
            WHERE target_reviewer_id=? AND status='PENDING'
            ORDER BY id DESC
        """, (senior_email,))
        return self.cursor.fetchall()

    def get_reviewed_for_senior(self, senior_email):
        self.cursor.execute("""
            SELECT id, file_name, junior_id, status, feedback
            FROM Files
            WHERE target_reviewer_id=? AND status IN ('APPROVED','REJECTED')
            ORDER BY id DESC
        """, (senior_email,))
        return self.cursor.fetchall()

    def update_review(self, f_id, status, feedback):
        now = datetime.datetime.now()
        self.cursor.execute("""
            UPDATE Files
            SET status=?, feedback=?, reviewed_at=?
            WHERE id=?
        """, (status, feedback, now, f_id))
        self.conn.commit()

    # get signature + hash + junior for verification
    def get_file_crypto_bundle(self, f_id):
        self.cursor.execute("""
            SELECT junior_id, file_name, signature, file_hash
            FROM Files
            WHERE id=?
        """, (f_id,))
        return self.cursor.fetchone()