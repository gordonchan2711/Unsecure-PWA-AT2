# Unsecure Social PWA

A social media progressive web app built with Flask and SQLite, originally created with intentional security vulnerabilities for educational purposes. This is **Version 4** — the fully patched version where all 16 vulnerabilities have been identified and fixed.

> Built for AT2 — Security Engineering. Vulnerabilities were introduced intentionally and fixed across V1 to V4.

---

## What the App Does

- Create an account and log in
- Post to a shared social feed
- View other users' profiles
- Send and receive direct messages
- Install as a PWA on your device

---

## Getting Started

### Run in GitHub Codespaces (Recommended)

1. Go to the repo on GitHub
2. Click the green **Code** button
3. Select the **Codespaces** tab
4. Click **Create codespace on main**
5. Wait for it to load — VS Code will open in your browser
6. In the terminal, run:

```bash
pip install -r requirements.txt
python main.py
```

7. Codespaces will show a popup saying a port is available — click **Open in Browser**
8. The app will open on port 5000

---

### Run Locally

Make sure you have Python 3.10+ installed, then:

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/Unsecure-PWA-AT2.git
cd Unsecure-PWA-AT2

# Install dependencies
pip install -r requirements.txt

# Run the app
python main.py
```

Then open your browser and go to `http://localhost:5000`

The database will be created automatically on first run with seeded users and posts.

---

### Default Login Credentials

These are seeded into the database on first run:

| Username | Password | Role |
|----------|----------|------|
| admin | password123 | Admin |
| GamerGirl | qwerty | User |
| TechNerd42 | letmein | User |
| CryptoKing | blockchain1 | User |
| Sarah_J | ilovecats99 | User |
| x0_h4ck3r | supersecret! | User |

---

## How to Install as a PWA

The app is a fully working Progressive Web App — you can install it on your device and use it like a native app.

### On Desktop (Chrome or Edge)

1. Open the app in Chrome or Edge
2. Look for the **install icon** in the address bar (a small computer icon on the right)
3. Click it and select **Install**
4. The app will open in its own window separate from the browser

### On Mobile (Android)

1. Open the app in Chrome
2. Tap the three-dot menu in the top right
3. Tap **Add to Home Screen**
4. Tap **Install**
5. The app icon will appear on your home screen

### On Mobile (iOS Safari)

1. Open the app in Safari
2. Tap the **Share** button at the bottom
3. Scroll down and tap **Add to Home Screen**
4. Tap **Add**

Once installed, the app works offline for static assets and will prompt you to install automatically via the **Install App** button in the navbar.

---

## How to Use the App

### Creating an Account

1. Click **Sign Up** in the navbar
2. Enter a username (3 to 30 characters), password (minimum 8 characters), date of birth and an optional bio
3. Click **Create Account**
4. You will be redirected to the login page

### Logging In

1. Enter your username and password on the home page
2. Click **Log In**
3. You will be taken to the feed

### Posting to the Feed

1. Log in and go to the **Feed** page
2. Type your post in the text box (max 500 characters)
3. Click **Post**
4. Your post will appear at the top of the feed

### Viewing a Profile

1. Click on any username in the feed
2. You will be taken to their profile page showing their username, bio and role
3. You must be logged in to view profiles

### Sending a Message

1. Click **Messages** in the navbar or sidebar
2. Enter the recipient's username in the **To** field
3. Type your message (max 1000 characters)
4. Click **Send**
5. The message will appear in their inbox

### Logging Out

Click **Log Out** in the sidebar on the feed or messages page. This clears your session completely.

---

## Environment Variables

For production use, set the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret key | Random per process (not persistent) |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | None (no external origins) |

Example:

```bash
export SECRET_KEY="your-long-random-secret-key-here"
export ALLOWED_ORIGINS="https://yourdomain.com"
python main.py
```

> If `SECRET_KEY` is not set, a random key is generated each time the app starts. This means all sessions will be cleared on restart. Always set it in production.

---

## Version Changelog

| Version | Issues Fixed |
|---------|-------------|
| **V1** | SQL injection, plaintext passwords, no rate limiting, hardcoded secret key |
| **V2** | Wildcard CORS, open redirect, no input validation, no duplicate username check |
| **V3** | IDOR on post author, no auth on /profile, no auth on /messages, timing side-channel |
| **V4** | Stored XSS in posts/messages/bio, IDOR on message sender, SQL injection in getUserProfile(), SQL injection in getMessages() and sendMessage() |

Full details for each vulnerability are documented in the GitHub Issues board.

---

## Security Notes

This app was built for a security engineering assignment. All 16 original vulnerabilities have been fixed in this version. The fixes include:

- Parameterized queries throughout to prevent SQL injection
- bcrypt password hashing — passwords are never stored in plain text
- Flask session management — no sensitive data in hidden form fields
- Input validation on all routes — server-side, not just client-side
- CORS restricted to trusted origins only
- Safe redirect validation — external URLs are blocked
- Jinja2 auto-escaping — `|safe` removed from all user-generated content
- Constant-time login to prevent timing side-channel attacks
- Rate limiting — 5 failed attempts per 60 seconds triggers a lockout

---

## Requirements

- Python 3.10 or higher
- pip packages listed in `requirements.txt`:
  - Flask
  - Flask-Cors
  - bcrypt
  - Flask-Limiter
  - Flask-WTF
  - Werkzeug

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Australian Privacy Principles](https://www.oaic.gov.au/privacy/australian-privacy-principles)
