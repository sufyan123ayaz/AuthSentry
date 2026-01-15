import sqlite3
import bcrypt
from security import ensure_schema, DB


def upsert_user(username: str, plain_password: str, email: str, is_admin: int):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    pw_hash = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt())

    # First try update
    cur.execute(
        "UPDATE users SET password=?, email=?, is_admin=? WHERE username=?",
        (pw_hash, email, is_admin, username)
    )

    # If nothing updated, insert
    if cur.rowcount == 0:
        cur.execute(
            "INSERT INTO users(username, password, email, is_admin) VALUES (?,?,?,?)",
            (username, pw_hash, email, is_admin)
        )

    # Ensure attempts row exists
    cur.execute(
        "INSERT OR IGNORE INTO attempts(username, count, blocked_until, last_attempt) VALUES (?,0,NULL,NULL)",
        (username,)
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    ensure_schema()
    upsert_user("admin", "admin123", "admin@example.com", 1)
    print("✅ DB migrated + Admin ready: admin / admin123")
