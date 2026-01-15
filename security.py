import os
import sqlite3
import time
import bcrypt
import smtplib
from email.mime.text import MIMEText

DB = "database.db"

MAX_USER_ATTEMPTS = 5
MAX_IP_ATTEMPTS = 12
USER_BLOCK_TIME = 30
IP_BLOCK_TIME = 60

OTP_TTL = 300  # seconds


def _table_columns(cur, table: str):
    cur.execute(f"PRAGMA table_info({table})")
    # cid, name, type, notnull, dflt_value, pk
    return cur.fetchall()


def _has_table(cur, table: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None


def _rebuild_users_if_needed(cur):
    """
    If existing users table does not have username as PRIMARY KEY,
    rebuild it into correct schema.
    """
    if not _has_table(cur, "users"):
        return

    cols = _table_columns(cur, "users")
    col_names = {c[1] for c in cols}
    # find username pk flag
    username_pk = False
    for c in cols:
        if c[1] == "username" and int(c[5] or 0) == 1:
            username_pk = True
            break

    if username_pk:
        return  # already good

    # Rebuild users table
    # Keep what we can: username, password, email, is_admin
    has_email = "email" in col_names
    has_is_admin = "is_admin" in col_names
    has_password = "password" in col_names
    has_username = "username" in col_names

    if not (has_username and has_password):
        # if extremely old/broken, just recreate fresh
        cur.execute("DROP TABLE IF EXISTS users")
        cur.execute("""
        CREATE TABLE users(
            username TEXT PRIMARY KEY,
            password BLOB NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """)
        return

    # create new table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users_new(
        username TEXT PRIMARY KEY,
        password BLOB NOT NULL,
        email TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # copy data
    if has_email and has_is_admin:
        cur.execute("""
            INSERT OR IGNORE INTO users_new(username, password, email, is_admin)
            SELECT username, password, email, is_admin FROM users
        """)
    elif has_email and not has_is_admin:
        cur.execute("""
            INSERT OR IGNORE INTO users_new(username, password, email, is_admin)
            SELECT username, password, email, 0 FROM users
        """)
    elif (not has_email) and has_is_admin:
        cur.execute("""
            INSERT OR IGNORE INTO users_new(username, password, email, is_admin)
            SELECT username, password, NULL, is_admin FROM users
        """)
    else:
        cur.execute("""
            INSERT OR IGNORE INTO users_new(username, password, email, is_admin)
            SELECT username, password, NULL, 0 FROM users
        """)

    # swap tables
    cur.execute("DROP TABLE users")
    cur.execute("ALTER TABLE users_new RENAME TO users")


def ensure_schema():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    # If users exists but wrong constraint -> rebuild
    _rebuild_users_if_needed(cur)

    # users (create if not exists)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password BLOB NOT NULL,
        email TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # migrate missing columns safely
    cur.execute("PRAGMA table_info(users)")
    ucols = {r[1] for r in cur.fetchall()}
    if "email" not in ucols:
        cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "is_admin" not in ucols:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    if "created_at" not in ucols:
        cur.execute("ALTER TABLE users ADD COLUMN created_at TEXT")

    # attempts
    cur.execute("""
    CREATE TABLE IF NOT EXISTS attempts(
        username TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0,
        blocked_until REAL,
        last_attempt REAL
    )
    """)

    # ip_attempts
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ip_attempts(
        ip TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0,
        blocked_until REAL,
        last_attempt REAL
    )
    """)

    # logs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL,
        username TEXT,
        ip TEXT,
        user_agent TEXT,
        success INTEGER,
        reason TEXT
    )
    """)

    # otp
    cur.execute("""
    CREATE TABLE IF NOT EXISTS otp_codes(
        username TEXT PRIMARY KEY,
        code_hash BLOB NOT NULL,
        expires_at REAL NOT NULL,
        created_at REAL NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def log_event(username: str, ip: str, user_agent: str, success: bool, reason: str):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO login_logs(ts, username, ip, user_agent, success, reason)
        VALUES (?,?,?,?,?,?)
    """, (time.time(), username, ip, (user_agent or "")[:200], 1 if success else 0, reason[:200]))
    conn.commit()
    conn.close()


def send_email_alert(subject: str, body: str):
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pw = os.getenv("SMTP_PASS")
    to_addr = os.getenv("ALERT_TO")

    if not (host and user and pw and to_addr):
        print(f"[ALERT-DEV] {subject}\n{body}\n")
        return

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr

    with smtplib.SMTP(host, port) as s:
        s.starttls()
        s.login(user, pw)
        s.send_message(msg)


def is_user_blocked(username: str):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT blocked_until FROM attempts WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    now = time.time()
    if row and row[0] and now < row[0]:
        return True, int(row[0] - now)
    return False, 0


def is_ip_blocked(ip: str):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT blocked_until FROM ip_attempts WHERE ip=?", (ip,))
    row = cur.fetchone()
    conn.close()

    now = time.time()
    if row and row[0] and now < row[0]:
        return True, int(row[0] - now)
    return False, 0


def record_failed_user_attempt(username: str):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT count FROM attempts WHERE username=?", (username,))
    row = cur.fetchone()
    now = time.time()

    blocked_now = False
    if row:
        count = (row[0] or 0) + 1
        if count >= MAX_USER_ATTEMPTS:
            blocked_now = True
            cur.execute(
                "UPDATE attempts SET count=?, blocked_until=?, last_attempt=? WHERE username=?",
                (count, now + USER_BLOCK_TIME, now, username)
            )
        else:
            cur.execute("UPDATE attempts SET count=?, last_attempt=? WHERE username=?", (count, now, username))
    else:
        count = 1
        cur.execute(
            "INSERT INTO attempts(username, count, blocked_until, last_attempt) VALUES (?,?,NULL,?)",
            (username, count, now)
        )

    conn.commit()
    conn.close()
    return count, blocked_now


def record_failed_ip_attempt(ip: str):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT count FROM ip_attempts WHERE ip=?", (ip,))
    row = cur.fetchone()
    now = time.time()

    blocked_now = False
    if row:
        count = (row[0] or 0) + 1
        if count >= MAX_IP_ATTEMPTS:
            blocked_now = True
            cur.execute(
                "UPDATE ip_attempts SET count=?, blocked_until=?, last_attempt=? WHERE ip=?",
                (count, now + IP_BLOCK_TIME, now, ip)
            )
        else:
            cur.execute("UPDATE ip_attempts SET count=?, last_attempt=? WHERE ip=?", (count, now, ip))
    else:
        count = 1
        cur.execute(
            "INSERT INTO ip_attempts(ip, count, blocked_until, last_attempt) VALUES (?,?,NULL,?)",
            (ip, count, now)
        )

    conn.commit()
    conn.close()
    return count, blocked_now


def reset_user_attempts(username: str):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("UPDATE attempts SET count=0, blocked_until=NULL WHERE username=?", (username,))
    conn.commit()
    conn.close()


def create_otp(username: str):
    ensure_schema()
    code = str(int(time.time() * 1000) % 1000000).zfill(6)
    code_hash = bcrypt.hashpw(code.encode(), bcrypt.gensalt())
    now = time.time()
    exp = now + OTP_TTL

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO otp_codes(username, code_hash, expires_at, created_at)
        VALUES (?,?,?,?)
        ON CONFLICT(username) DO UPDATE SET
            code_hash=excluded.code_hash,
            expires_at=excluded.expires_at,
            created_at=excluded.created_at
    """, (username, code_hash, exp, now))
    conn.commit()
    conn.close()
    return code, OTP_TTL


def verify_otp(username: str, code: str):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT code_hash, expires_at FROM otp_codes WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, "OTP not found. Please request again."

    code_hash, expires_at = row
    if time.time() > float(expires_at):
        return False, "OTP expired. Please request again."

    if bcrypt.checkpw(code.encode(), code_hash):
        return True, "OK"
    return False, "Invalid OTP"
