import sqlite3 as sql
import os
import bcrypt
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database_files", "database.db")
LOG_PATH = os.path.join(BASE_DIR, "visitor_log.txt")

# rate limiting store — keeps track of failed attempts per username
_login_attempts = {}
MAX_ATTEMPTS   = 5
LOCKOUT_WINDOW = 60

# dummy hash so bcrypt always runs even when username doesn't exist
# took me a while to figure out why timing was still leaking without this
_DUMMY_HASH = bcrypt.hashpw(b"dummy_password_for_timing", bcrypt.gensalt()).decode("utf-8")


def _is_locked_out(username):
    now      = time.time()
    attempts = [t for t in _login_attempts.get(username, []) if now - t < LOCKOUT_WINDOW]
    _login_attempts[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def _record_attempt(username):
    _login_attempts.setdefault(username, []).append(time.time())


def insertUser(username, password, DoB, bio=""):
    # FIX: hash password with bcrypt before storing — never plain text
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
    # FIX: rate limiting — blocks brute force after 5 attempts
    if _is_locked_out(username):
        return False

    con = sql.connect(DB_PATH)
    cur = con.cursor()

    # FIX: parameterized query — no sql injection
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    con.close()

    if user_row is None:
        # FIX: still run bcrypt on dummy hash so response time is the same
        # without this, you could tell if a username exists just by timing the response
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH.encode("utf-8"))
        _record_attempt(username)
        return False

    stored_hash = user_row[2]
    try:
        # FIX: bcrypt comparison — never comparing plain text passwords
        match = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        match = False

    if not match:
        _record_attempt(username)
        return False

    # clear attempts on successful login
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
    # author always comes from the session now, not a form field
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # FIX: parameterized query
    cur.execute("INSERT INTO posts (author, content) VALUES (?,?)", (author, content))
    con.commit()
    con.close()


def getPosts():
    # note: |safe was removed from the template so content renders as plain text
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    con.close()
    return data


def getUserProfile(username):
    # FIX: parameterized query — /profile?user=admin'-- no longer works
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
    # FIX: parameterized query — inbox can't be hijacked via ?user= injection
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
    # FIX: parameterized query on all three fields
    # sender is passed in from the session in main.py — not from the form anymore
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
