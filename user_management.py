import sqlite3 as sql
import os
import bcrypt
import time

# ─────────────────────────────────────────────────────────────────────────────
#  user_management.py  —  Version 3
#
#  FIXED (on top of V1 + V2):
#    - Timing side-channel: constant-time comparison regardless of username existence
#
#  STILL VULNERABLE (intentional — issues #17–20):
#    - Stored XSS via post content (|safe in feed.html)
#    - IDOR on message sender (hidden field — kept in template)
#    - SQL Injection in getUserProfile()
#    - SQL Injection in getMessages() and sendMessage()
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database_files", "database.db")
LOG_PATH = os.path.join(BASE_DIR, "visitor_log.txt")

# ── Rate Limiting (carried from V1) ──────────────────────────────────────────
_login_attempts = {}
MAX_ATTEMPTS   = 5
LOCKOUT_WINDOW = 60

# Dummy hash used for constant-time comparison when username doesn't exist
# FIX: prevents timing side-channel — bcrypt always runs even for unknown users
_DUMMY_HASH = bcrypt.hashpw(b"dummy_password_for_timing", bcrypt.gensalt()).decode("utf-8")


def _is_locked_out(username):
    now      = time.time()
    attempts = [t for t in _login_attempts.get(username, []) if now - t < LOCKOUT_WINDOW]
    _login_attempts[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def _record_attempt(username):
    _login_attempts.setdefault(username, []).append(time.time())


def insertUser(username, password, DoB, bio=""):
    """FIX: bcrypt hash. Duplicate check handled in main.py."""
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
    """
    FIX: Constant-time login — bcrypt.checkpw always runs regardless of whether
    the username exists, eliminating the timing side-channel.
    """
    if _is_locked_out(username):
        return False

    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    con.close()

    if user_row is None:
        # FIX: Still run bcrypt against dummy hash — same timing as a real check
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH.encode("utf-8"))
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
    """Parameterized query. Author now comes from session (fixed in main.py)."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("INSERT INTO posts (author, content) VALUES (?,?)", (author, content))
    con.commit()
    con.close()


def getPosts():
    """NOTE: Content still rendered with |safe in feed.html — Stored XSS (#17) remains."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    con.close()
    return data


def getUserProfile(username):
    """
    STILL VULNERABLE (#19): SQL Injection via f-string — intentionally left for exercise.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(f"SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = '{username}'")
    row = cur.fetchone()
    con.close()
    return row


def getMessages(username):
    """
    STILL VULNERABLE (#20): SQL Injection via f-string — intentionally left for exercise.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(f"SELECT * FROM messages WHERE recipient = '{username}' ORDER BY id DESC")
    rows = cur.fetchall()
    con.close()
    return rows


def sendMessage(sender, recipient, body):
    """
    STILL VULNERABLE (#20): SQL Injection via f-string — intentionally left for exercise.
    STILL VULNERABLE (#18): sender from hidden field — intentionally left for exercise.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(f"INSERT INTO messages (sender, recipient, body) VALUES ('{sender}', '{recipient}', '{body}')")
    con.commit()
    con.close()


def getVisitorCount():
    try:
        with open(LOG_PATH, "r") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0
