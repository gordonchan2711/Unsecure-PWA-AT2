import os
import sys
import sqlite3
import subprocess
import secrets
from flask import Flask, render_template, request, redirect, session
from flask_cors import CORS
import user_management as db

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")


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

# STILL VULNERABLE: Wildcard CORS
CORS(app)

# FIX: Secret key loaded from environment variable, falls back to a random
# generated key per-process (not persistent across restarts, but not hardcoded).
# In production, set the SECRET_KEY environment variable.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))


# ── Home / Login ──────────────────────────────────────────────────────────────

@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    # STILL VULNERABLE: Open Redirect
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    # STILL VULNERABLE: Reflected XSS via |safe in template
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg)

    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
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
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB      = request.form["dob"]
        bio      = request.form.get("bio", "")
        # STILL VULNERABLE: No duplicate username check
        # STILL VULNERABLE: No input validation
        db.insertUser(username, password, DoB, bio)
        return render_template("index.html", msg="Account created! Please log in.")
    else:
        return render_template("signup.html")


# ── Social Feed ───────────────────────────────────────────────────────────────

@app.route("/feed.html", methods=["POST", "GET"])
def feed():
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        post_content = request.form["content"]
        # STILL VULNERABLE: IDOR — username from hidden form field
        username = request.form.get("username", "Anonymous")
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
        return redirect(request.args.get("url"), code=302)
    username = request.args.get("user", "")
    profile_data = db.getUserProfile(username)
    return render_template("profile.html", profile=profile_data, username=username)


# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    # STILL VULNERABLE: No authentication
    if request.method == "POST":
        sender    = request.form.get("sender", "Anonymous")
        recipient = request.form.get("recipient", "")
        body      = request.form.get("body", "")
        db.sendMessage(sender, recipient, body)
        msgs = db.getMessages(recipient)
        return render_template("messages.html", messages=msgs, username=sender, recipient=recipient)
    else:
        username = request.args.get("user", "Guest")
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
