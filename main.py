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

# Carried from V2: restricted CORS
if ALLOWED_ORIGINS and ALLOWED_ORIGINS != [""]:
    CORS(app, origins=ALLOWED_ORIGINS)
else:
    CORS(app, origins=[])

# Carried from V1: env-based secret key
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

SAFE_REDIRECT_HOSTS = {"localhost", "127.0.0.1"}


def _safe_redirect(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.netloc or parsed.netloc.split(":")[0] in SAFE_REDIRECT_HOSTS:
        return redirect(url, code=302)
    return None


def _require_login():
    """FIX: Returns the logged-in username or None."""
    return session.get("username")


# ── Home / Login ──────────────────────────────────────────────────────────────

@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
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

        if not username or not password:
            return render_template("index.html", msg="Username and password are required.")
        if len(username) > 50 or len(password) > 200:
            return render_template("index.html", msg="Input too long.")

        isLoggedIn = db.retrieveUsers(username, password)
        if isLoggedIn:
            # FIX: Store username in server-side session
            session["username"] = username
            posts = db.getPosts()
            return render_template("feed.html", username=username, state=True, posts=posts)
        else:
            return render_template("index.html", msg="Invalid credentials. Please try again.")


# ── Logout ────────────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


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

        if not username or not password or not DoB:
            return render_template("signup.html", msg="All fields are required.")
        if len(username) < 3 or len(username) > 30:
            return render_template("signup.html", msg="Username must be 3–30 characters.")
        if len(password) < 8:
            return render_template("signup.html", msg="Password must be at least 8 characters.")
        if len(bio) > 200:
            return render_template("signup.html", msg="Bio must be under 200 characters.")
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

    # FIX: IDOR — get username from session, not from form field
    logged_in_user = _require_login()
    if not logged_in_user:
        return redirect("/?msg=Please log in to access the feed.")

    if request.method == "POST":
        post_content = request.form.get("content", "").strip()

        if not post_content:
            posts = db.getPosts()
            return render_template("feed.html", username=logged_in_user, state=True, posts=posts,
                                   msg="Post content cannot be empty.")
        if len(post_content) > 500:
            posts = db.getPosts()
            return render_template("feed.html", username=logged_in_user, state=True, posts=posts,
                                   msg="Post too long (max 500 characters).")

        # FIX: Use session username — not the hidden form field
        db.insertPost(logged_in_user, post_content)
        posts = db.getPosts()
        return render_template("feed.html", username=logged_in_user, state=True, posts=posts)
    else:
        posts = db.getPosts()
        return render_template("feed.html", username=logged_in_user, state=True, posts=posts)


# ── User Profile ──────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    # FIX: Authentication required
    logged_in_user = _require_login()
    if not logged_in_user:
        return redirect("/?msg=Please log in to view profiles.")

    if request.args.get("url"):
        safe = _safe_redirect(request.args.get("url"))
        if safe:
            return safe

    username = request.args.get("user", "").strip()
    if not username or len(username) > 50:
        return render_template("profile.html", profile=None, username="")
    profile_data = db.getUserProfile(username)
    return render_template("profile.html", profile=profile_data, username=username)


# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    # FIX: Authentication required — users can only see their own inbox
    logged_in_user = _require_login()
    if not logged_in_user:
        return redirect("/?msg=Please log in to view messages.")

    if request.method == "POST":
        # FIX: sender is always the logged-in user — not from hidden field
        sender    = logged_in_user
        recipient = request.form.get("recipient", "").strip()
        body      = request.form.get("body", "").strip()

        if not recipient or not body:
            msgs = db.getMessages(logged_in_user)
            return render_template("messages.html", messages=msgs, username=logged_in_user,
                                   recipient=recipient, msg="Recipient and message body are required.")
        if len(body) > 1000:
            msgs = db.getMessages(logged_in_user)
            return render_template("messages.html", messages=msgs, username=logged_in_user,
                                   recipient=recipient, msg="Message too long (max 1000 characters).")

        db.sendMessage(sender, recipient, body)
        msgs = db.getMessages(logged_in_user)
        return render_template("messages.html", messages=msgs, username=logged_in_user, recipient=recipient)
    else:
        # FIX: Always show the logged-in user's inbox — ignore ?user= param
        msgs = db.getMessages(logged_in_user)
        return render_template("messages.html", messages=msgs, username=logged_in_user, recipient=logged_in_user)


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
