import sqlite3 as sql
import time
import os
import bcrypt

# ─────────────────────────────────────────────────────────────────────────────
#  user_management.py  —  Version 1
#
#  FIXED:
#    1. SQL Injection       — parameterized queries throughout
#    2. Plaintext passwords — bcrypt hashing applied
#    3. Rate limiting       — in-memory lockout after 5 failed attempts
#
#  STILL VULNERABLE (intentional):
#    - Timing side-channel
#    - No input validation
#    - IDOR (username from hidden field)
#    - No duplicate username check
#    - No auth checks on profile/messages
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database_files", "database.db")
LOG_PATH = os.path.join(BASE_DIR, "visitor_log.txt")

# ── Rate Limiting ─────────────────────────────────────────────────────────────
_login_attempts = {}
MAX_ATTEMPTS   = 5
LOCKOUT_WINDOW = 60  # seconds


def _is_locked_out(username):
    now      = time.time()
    attempts = [t for t in _login_attempts.get(username, []) if now - t < LOCKOUT_WINDOW]
    _login_attempts[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def _record_attempt(username):
    _login_attempts.setdefault(username, []).append(time.time())


def insertUser(username, password, DoB, bio=""):
    """FIX: bcrypt hash. STILL VULNERABLE: no duplicate check."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, bio) VALUES (?,?,?,?)",
        (username, hashed, DoB, bio),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    """FIX: parameterized queries, bcrypt check, rate limiting."""
    if _is_locked_out(username):
        return False

    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    con.close()

    if user_row is None:
        _record_attempt(username)
        return False

    stored_hash = user_row[2]
    try:
        match = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        match = False

    if not match:
        _record_attempt(username)
        return False

    _login_attempts.pop(username, None)

    try:
        with open(LOG_PATH, "r") as f:
            count = int(f.read().strip() or 0)
        with open(LOG_PATH, "w") as f:
            f.write(str(count + 1))
    except Exception:
        pass

    return True


def insertPost(author, content):
    """FIX: parameterized query. STILL VULNERABLE: IDOR on author."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("INSERT INTO posts (author, content) VALUES (?,?)", (author, content))
    con.commit()
    con.close()


def getPosts():
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    con.close()
    return data


def getUserProfile(username):
    """FIX: parameterized query. STILL VULNERABLE: no auth check."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = ?",
        (username,)
    )
    row = cur.fetchone()
    con.close()
    return row


def getMessages(username):
    """FIX: parameterized query. STILL VULNERABLE: no auth check."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "SELECT * FROM messages WHERE recipient = ? ORDER BY id DESC",
        (username,)
    )
    rows = cur.fetchall()
    con.close()
    return rows


def sendMessage(sender, recipient, body):
    """FIX: parameterized query. STILL VULNERABLE: sender spoofable."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO messages (sender, recipient, body) VALUES (?,?,?)",
        (sender, recipient, body)
    )
    con.commit()
    con.close()


def getVisitorCount():
    try:
        with open(LOG_PATH, "r") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0
