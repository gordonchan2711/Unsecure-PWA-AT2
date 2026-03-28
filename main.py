import os
import sys
import sqlite3
import subprocess
import secrets
from flask import Flask, render_template, request, redirect, session, abort
from flask_cors import CORS
import user_management as db

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")

# FIX: Restrict CORS to same origin / trusted origins only
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "").split(",")


def _tables_exist():
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        tables = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()
        return {"users", "posts", "messages"}.issubset(tables)
    except Exception:
        return False


def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database_files"), exist_ok=True)
    if not os.path.exists(DB_PATH) or not _tables_exist():
        print("[SocialPWA] Setting up database...")
        result = subprocess.run(
            [sys.executable, SETUP_SCRIPT],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print("[SocialPWA] WARNING: setup_db failed:", result.stderr)
    else:
        print("[SocialPWA] Database already exists — skipping setup.")


init_db()

app = Flask(__name__)

# FIX: CORS restricted — only allow same-origin or explicitly listed origins
if ALLOWED_ORIGINS and ALLOWED_ORIGINS != [""]:
    CORS(app, origins=ALLOWED_ORIGINS)
else:
    # No external origins permitted by default
    CORS(app, origins=[])

# FIX: Secret key from environment variable
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# FIX: Allowed redirect targets — open redirect is fixed
SAFE_REDIRECT_HOSTS = {"localhost", "127.0.0.1"}


def _safe_redirect(url):
    """FIX: Only allow redirects to same-host URLs, block external redirects."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    # Relative URLs are fine; absolute URLs must match a safe host
    if not parsed.netloc or parsed.netloc.split(":")[0] in SAFE_REDIRECT_HOSTS:
        return redirect(url, code=302)
    return None  # Blocked


# ── Home / Login ──────────────────────────────────────────────────────────────

@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    # FIX: Open redirect — validate URL before redirecting
    if request.method == "GET" and request.args.get("url"):
        safe = _safe_redirect(request.args.get("url"))
        if safe:
            return safe
        return render_template("index.html", msg="Invalid redirect URL.")

    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg)

    elif request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # FIX: Basic input validation
        if not username or not password:
            return render_template("index.html", msg="Username and password are required.")
        if len(username) > 50 or len(password) > 200:
            return render_template("index.html", msg="Input too long.")

        isLoggedIn = db.retrieveUsers(username, password)
        if isLoggedIn:
            posts = db.getPosts()
            return render_template("feed.html", username=username, state=isLoggedIn, posts=posts)
        else:
            return render_template("index.html", msg="Invalid credentials. Please try again.")


# ── Sign Up ───────────────────────────────────────────────────────────────────

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        safe = _safe_redirect(request.args.get("url"))
        if safe:
            return safe
        return render_template("signup.html", msg="Invalid redirect URL.")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        DoB      = request.form.get("dob", "").strip()
        bio      = request.form.get("bio", "").strip()

        # FIX: Input validation
        if not username or not password or not DoB:
            return render_template("signup.html", msg="All fields are required.")
        if len(username) < 3 or len(username) > 30:
            return render_template("signup.html", msg="Username must be 3–30 characters.")
        if len(password) < 8:
            return render_template("signup.html", msg="Password must be at least 8 characters.")
        if len(bio) > 200:
            return render_template("signup.html", msg="Bio must be under 200 characters.")

        # FIX: Duplicate username check
        if db.getUserProfile(username) is not None:
            return render_template("signup.html", msg="Username already taken. Please choose another.")

        db.insertUser(username, password, DoB, bio)
        return render_template("index.html", msg="Account created! Please log in.")
    else:
        return render_template("signup.html")


# ── Social Feed ───────────────────────────────────────────────────────────────

@app.route("/feed.html", methods=["POST", "GET"])
def feed():
    if request.method == "GET" and request.args.get("url"):
        safe = _safe_redirect(request.args.get("url"))
        if safe:
            return safe

    if request.method == "POST":
        post_content = request.form.get("content", "").strip()
        # STILL VULNERABLE: IDOR — username from hidden form field
        username = request.form.get("username", "Anonymous")

        # FIX: Validate post content
        if not post_content:
            posts = db.getPosts()
            return render_template("feed.html", username=username, state=True, posts=posts,
                                   msg="Post content cannot be empty.")
        if len(post_content) > 500:
            posts = db.getPosts()
            return render_template("feed.html", username=username, state=True, posts=posts,
                                   msg="Post too long (max 500 characters).")

        db.insertPost(username, post_content)
        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)
    else:
        posts = db.getPosts()
        return render_template("feed.html", username="Guest", state=True, posts=posts)


# ── User Profile ──────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    # STILL VULNERABLE: No authentication check
    if request.args.get("url"):
        safe = _safe_redirect(request.args.get("url"))
        if safe:
            return safe
    username = request.args.get("user", "").strip()
    # FIX: Input validation on username parameter
    if not username or len(username) > 50:
        return render_template("profile.html", profile=None, username="")
    profile_data = db.getUserProfile(username)
    return render_template("profile.html", profile=profile_data, username=username)


# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    # STILL VULNERABLE: No authentication
    if request.method == "POST":
        sender    = request.form.get("sender", "Anonymous").strip()
        recipient = request.form.get("recipient", "").strip()
        body      = request.form.get("body", "").strip()

        # FIX: Input validation
        if not recipient or not body:
            msgs = db.getMessages(sender)
            return render_template("messages.html", messages=msgs, username=sender,
                                   recipient=recipient, msg="Recipient and message body are required.")
        if len(body) > 1000:
            msgs = db.getMessages(sender)
            return render_template("messages.html", messages=msgs, username=sender,
                                   recipient=recipient, msg="Message too long (max 1000 characters).")

        db.sendMessage(sender, recipient, body)
        msgs = db.getMessages(recipient)
        return render_template("messages.html", messages=msgs, username=sender, recipient=recipient)
    else:
        username = request.args.get("user", "Guest").strip()
        msgs = db.getMessages(username)
        return render_template("messages.html", messages=msgs, username=username, recipient=username)


# ── Success Page ──────────────────────────────────────────────────────────────

@app.route("/success.html")
def success():
    msg = request.args.get("msg", "Your action was completed successfully.")
    return render_template("success.html", msg=msg)


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
