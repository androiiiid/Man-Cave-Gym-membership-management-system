import getpass
import os
import re
import secrets
import sys
import threading
import time
import mysql.connector
from datetime import date, datetime, timedelta
from functools import wraps
from hmac import compare_digest

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# ======================================================================
# Settings
# ======================================================================

SECRET_KEY_FILE = os.path.join(app.root_path, ".secret_key")
_lock = threading.Lock()  # serialize account changes within this Flask process

IDLE_TIMEOUT = 30 * 60        # log out after 30 minutes without activity (unless "remember me")
REMEMBER_DAYS = 1            # how long "remember me" keeps you logged in
MAX_PASSWORD_LENGTH = 128     # stops giant passwords from slowing the server down

LOGIN_MAX_FAILS_PER_EMAIL = 5
LOGIN_MAX_FAILS_PER_IP = 20
LOCKOUT_SECONDS = 15 * 60



def load_secret_key():
    """Use SECRET_KEY from the environment, or create a random one the first time and keep it
    in .secret_key. It signs the session cookie, so anyone who knows it can forge logins:
    never share it or commit it to git."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    try:
        fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()
    


app.secret_key = load_secret_key()

app.config.update(
    SESSION_COOKIE_NAME="mancave_session",
    SESSION_COOKIE_HTTPONLY=True,       # JavaScript can't read the cookie (limits XSS damage)
    SESSION_COOKIE_SAMESITE="Lax",      # browser won't send it on cross-site POSTs (extra CSRF layer)
    # Only sent over HTTPS when COOKIE_SECURE=1. Leave it off while testing over plain http
    # (localhost or your phone on Wi-Fi), turn it on once the site is served with HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=REMEMBER_DAYS),
    MAX_CONTENT_LENGTH=64 * 1024,       # reject huge requests
)
def get_db():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD", ""),
        database=os.environ.get("DB_NAME", "mancave"),
    )
# ======================================================================
# Validation rules (same as register.js)
# ======================================================================

NAME_RE = re.compile(r"[A-Za-z][A-Za-z .'-]*")
MOBILE_RE = re.compile(r"09\d{9}|\+639\d{9}")
EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]{2,}")
USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,50}")

# Used when the email isn't found, so a wrong email takes as long to reject as a wrong
# password (stops people from finding registered emails by timing the response).
DUMMY_HASH = generate_password_hash("not-a-real-password")

PASSWORD_RULES = [
    ("at least 8 characters", lambda p: len(p) >= 8),
    ("a lowercase letter", lambda p: re.search(r"[a-z]", p) is not None),
    ("an uppercase letter", lambda p: re.search(r"[A-Z]", p) is not None),
    ("an underscore ( _ )", lambda p: "_" in p),
    ("a number", lambda p: re.search(r"\d", p) is not None),
]

# ======================================================================
# MySQL user storage
# ======================================================================


def load_users():
    """Return all user rows for the admin dashboard and duplicate checks."""
    db = get_db()
    try:
        cur = db.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM members")
            return cur.fetchall()
        finally:
            cur.close()
    finally:
        db.close()


def find_user_by_email(email):
    db = get_db()
    try:
        cur = db.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM members WHERE email = %s", (email,))
            return cur.fetchone()
        finally:
            cur.close()
    finally:
        db.close()


def find_user_by_id(user_id):
    db = get_db()
    try:
        cur = db.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM members WHERE id = %s", (user_id,))
            return cur.fetchone()
        finally:
            cur.close()
    finally:
        db.close()


def insert_user(user):
    db = get_db()
    try:
        cur = db.cursor()
        try:
            cur.execute(
                """INSERT INTO members
                   (username, email, first_name, last_name, mobile, password_hash, bday, role, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    user["username"], user["email"], user["first_name"], user["last_name"],
                    user["mobile"], user["password_hash"], user["bday"], user["role"], user["created_at"],
                ),
            )
            db.commit()
        finally:
            cur.close()
    finally:
        db.close()


def set_user_role(user_id, role):
    db = get_db()
    try:
        cur = db.cursor()
        try:
            cur.execute("UPDATE members SET role = %s WHERE id = %s", (role, user_id))
            db.commit()
        finally:
            cur.close()
    finally:
        db.close()


def update_user_password_hash(user_id, password_hash):
    db = get_db()
    try:
        cur = db.cursor()
        try:
            cur.execute(
                "UPDATE members SET password_hash = %s WHERE id = %s",
                (password_hash, user_id),
            )
            db.commit()
        finally:
            cur.close()
    finally:
        db.close()


# ======================================================================
# Login throttling (in memory: resets when the server restarts)
# ======================================================================

_failures = {}
_failures_lock = threading.Lock()


def _recent_failures(key):
    cutoff = time.time() - LOCKOUT_SECONDS
    kept = [t for t in _failures.get(key, []) if t > cutoff]
    if kept:
        _failures[key] = kept
    else:
        _failures.pop(key, None)
    return kept


def is_locked(ip, email):
    with _failures_lock:
        return (
            len(_recent_failures(("email", email))) >= LOGIN_MAX_FAILS_PER_EMAIL
            or len(_recent_failures(("ip", ip))) >= LOGIN_MAX_FAILS_PER_IP
        )


def record_failure(ip, email):
    with _failures_lock:
        if len(_failures) > 10000:  # keep memory bounded
            _failures.clear()
        now = time.time()
        _failures.setdefault(("email", email), []).append(now)
        _failures.setdefault(("ip", ip), []).append(now)


def clear_failures(email):
    with _failures_lock:
        _failures.pop(("email", email), None)


# ======================================================================
# Sessions, CSRF protection and security headers
# ======================================================================


def csrf_token():
    """A random token stored in the session. Every form on the site includes it."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def session_housekeeping():
    """Log out idle users. The timestamp lives inside the signed cookie, so it can't be edited."""
    if request.endpoint == "static" or "user_id" not in session:
        return
    now = int(time.time())
    if not session.get("remember") and now - session.get("last_seen", 0) > IDLE_TIMEOUT:
        session.clear()
        g.session_expired = True
        return
    session["last_seen"] = now


@app.before_request
def check_csrf():
    """Every POST must carry the token from the session, or it is rejected."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "") or request.headers.get("X-CSRFToken", "")
        expected = session.get("_csrf", "")
        if not expected or not compare_digest(sent.encode(), expected.encode()):
            abort(400, description="Your session expired or the form was invalid. Please go back, reload the page and try again.")


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://images.unsplash.com; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    # Pages are never cached, so the Back button after logging out can't show private pages
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    return response



# ======================================================================
# Who is logged in?
# ======================================================================


def current_user():
    """The logged-in user, looked up in MySQL on every request, so a deleted user or a
    changed role takes effect immediately instead of waiting for the cookie to expire."""
    if "user" not in g:
        uid = session.get("user_id")
        g.user = None
        if uid is not None:
            g.user = find_user_by_id(uid)
    return g.user


def is_admin(user):
    return user is not None and user.get("role") == "admin"


def home_for(user):
    return url_for("admin_dashboard") if is_admin(user) else url_for("index")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            expired = g.get("session_expired", False)
            session.clear()
            return redirect(url_for("login", expired=1) if expired else url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not is_admin(current_user()):
            abort(403)
        return view(*args, **kwargs)

    return wrapped


# ======================================================================
# Error pages
# ======================================================================

ERROR_MESSAGES = {
    400: "Your session expired or the form was invalid. Please go back, reload the page and try again.",
    403: "You don't have permission to open this page.",
    404: "We couldn't find that page.",
    405: "That action isn't allowed here.",
    413: "That request was too large.",
}


@app.errorhandler(HTTPException)
def handle_http_error(error):
    code = error.code or 500
    message = ERROR_MESSAGES.get(code, "Something went wrong.")
    # Custom text passed to abort(400, description=...) wins
    if code == 400 and error.description and error.description != HTTPException.description:
        message = error.description
    back = home_for(current_user()) if current_user() else url_for("login")
    return render_template("error.html", code=code, message=message, back=back), code


# ======================================================================
# Routes
# ======================================================================


@app.route("/")
@login_required
def index():
    """Main landing page: only reachable after logging in."""
    return render_template("index.html", user=current_user())


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(home_for(current_user()))

    form = {
        "username": "", "bday": "", "first_name": "", "last_name": "",
        "number": "", "email": "",
    }
    errors = []
    invalid = set()  # field ids that get a red border

    if request.method == "POST":
        form = {
            "username": request.form.get("username", "").strip(),
            "bday": request.form.get("bday", "").strip(),
            "first_name": request.form.get("first_name", "").strip(),
            "last_name": request.form.get("last_name", "").strip(),
            "number": request.form.get("number", "").strip(),
            "email": request.form.get("email", "").strip().lower(),
        }
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        def fail(field, message):
            errors.append(message)
            invalid.add(field)

        if not form["username"]:
            fail("username", "Username is required.")
        elif not USERNAME_RE.fullmatch(form["username"]):
            fail("username", "Username may contain letters, numbers, periods, hyphens and underscores.")

        bday = None
        if not form["bday"]:
            fail("bday", "Birthday is required.")
        else:
            try:
                bday = date.fromisoformat(form["bday"])
                if bday > date.today():
                    fail("bday", "Birthday cannot be in the future.")
            except ValueError:
                fail("bday", "Enter a valid birthday.")

        # First name
        if not form["first_name"]:
            fail("first_name", "First name is required.")
        elif not NAME_RE.fullmatch(form["first_name"]):
            fail("first_name", "First name may only contain letters, spaces, apostrophes, periods and hyphens.")

        # Last name
        if not form["last_name"]:
            fail("last_name", "Last name is required.")
        elif not NAME_RE.fullmatch(form["last_name"]):
            fail("last_name", "Last name may only contain letters, spaces, apostrophes, periods and hyphens.")

        # Mobile number
        if not form["number"]:
            fail("number", "Mobile number is required.")
        elif not MOBILE_RE.fullmatch(form["number"]):
            fail("number", "Mobile number must be 09XXXXXXXXX or +639XXXXXXXXX.")

        # Email
        if not form["email"]:
            fail("email", "Email address is required.")
        elif not EMAIL_RE.fullmatch(form["email"]):
            fail("email", "Please enter a valid email address.")

        # Password
        if not password:
            fail("password", "Password is required.")
        elif len(password) > MAX_PASSWORD_LENGTH:
            fail("password", f"Password must be {MAX_PASSWORD_LENGTH} characters or fewer.")
        else:
            missing = [label for label, check in PASSWORD_RULES if not check(password)]
            if missing:
                fail("password", "Password needs " + ", ".join(missing) + ".")

        # Confirm password
        if not confirm:
            fail("confirm_password", "Please confirm your password.")
        elif confirm != password:
            fail("confirm_password", "Passwords do not match.")

        # Store +639XXXXXXXXX as 09XXXXXXXXX so the same number can't register twice
        mobile = form["number"]
        if mobile.startswith("+63"):
            mobile = "0" + mobile[3:]

        # Duplicate checks and insertion happen under one lock for this app process.
        if not errors:
            with _lock:
                users = load_users()

                if any((u.get("username") or "").lower() == form["username"].lower() for u in users):
                    fail("username", "That username is already taken.")
                if any(u["email"] == form["email"] for u in users):
                    fail("email", "That email address is already registered.")
                if any((u.get("mobile") or "") == mobile for u in users):
                    fail("number", "That mobile number is already registered.")

                # Save the user with a password hash, never the plain-text password.
                if not errors:
                    insert_user(
                        {
                            "username": form["username"],
                            "bday": bday,
                            "first_name": form["first_name"],
                            "last_name": form["last_name"],
                            "mobile": mobile,
                            "email": form["email"],
                            "password_hash": generate_password_hash(password),
                            # Everyone who signs up is a member. Admins are only made with
                            # `py app.py create-admin`, never from this form.
                            "role": "member",
                            "created_at": datetime.now(),
                        }
                    )
                    return redirect(url_for("login", registered=1))

    return render_template("register.html", form=form, errors=errors, invalid=invalid)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Already logged in? Skip the form.
    if current_user():
        return redirect(home_for(current_user()))

    email = ""
    errors = []
    invalid = set()
    status = 200

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"
        ip = request.remote_addr or "unknown"

        if not email:
            errors.append("Email address is required.")
            invalid.add("email")
        if not password:
            errors.append("Password is required.")
            invalid.add("password")

        if not errors and is_locked(ip, email):
            errors.append("Too many failed attempts. Please try again in 15 minutes.")
            status = 429

        if not errors:
            user = find_user_by_email(email)
            too_long = len(password) > MAX_PASSWORD_LENGTH
            stored_password = user["password_hash"] if user else DUMMY_HASH
            legacy_plaintext = False
            try:
                password_ok = check_password_hash(stored_password, "" if too_long else password)
            except (TypeError, ValueError):
                # Legacy accounts may have a plain-text value in password_hash.
                password_ok = False

            if user and not too_long and not password_ok and "$" not in str(stored_password):
                legacy_plaintext = compare_digest(str(stored_password).encode(), password.encode())
                password_ok = legacy_plaintext

            if user and password_ok and not too_long:
                if legacy_plaintext:
                    # Upgrade the legacy plain-text value after the user proves they know it.
                    update_user_password_hash(user["id"], generate_password_hash(password))
                clear_failures(email)
                session.clear()  # new session on login (prevents session fixation)
                session["user_id"] = user["id"]
                session["remember"] = remember
                session["last_seen"] = int(time.time())
                session.permanent = remember  # permanent = cookie survives closing the browser
                return redirect(home_for(user))

            record_failure(ip, email)
            # Same message for a wrong email and a wrong password, on purpose
            errors.append("Incorrect email or password.")
            invalid.update({"email", "password"})

    return (
        render_template(
            "login.html",
            email=email,
            errors=errors,
            invalid=invalid,
            registered=request.args.get("registered"),
            expired=request.args.get("expired"),
        ),
        status,
    )


@app.route("/admin")
@admin_required
def admin_dashboard():
    """Admin-only dashboard. Everyone else gets a 403 page."""
    users = load_users()
    cutoff = datetime.now() - timedelta(days=7)

    def joined_recently(user):
        try:
            joined = user["created_at"]
            if isinstance(joined, str):
                joined = datetime.fromisoformat(joined)
            return joined >= cutoff
        except (KeyError, TypeError, ValueError):
            return False

    # Only pass what the page needs: password hashes never leave app.py
    rows = [
        {
            "id": u["id"],
            "name": f'{u["first_name"]} {u["last_name"]}',
            "email": u["email"],
            "mobile": u.get("mobile") or "—",
            "role": u.get("role", "member"),
            "joined": (
                u["created_at"].strftime("%Y-%m-%d")
                if hasattr(u.get("created_at"), "strftime")
                else str(u.get("created_at", ""))[:10]
            ),
        }
        for u in sorted(users, key=lambda u: u["id"], reverse=True)
    ]
    stats = {
        "members": sum(1 for u in users if u.get("role", "member") != "admin"),
        "admins": sum(1 for u in users if u.get("role") == "admin"),
        "new_week": sum(1 for u in users if joined_recently(u)),
    }
    return render_template("admin.html", user=current_user(), rows=rows, stats=stats)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ======================================================================
# Command line: create or promote an admin
#   py app.py create-admin
# ======================================================================


def create_admin():
    print("Create or promote an admin account\n")
    email = input("Admin email: ").strip().lower()
    if not EMAIL_RE.fullmatch(email):
        sys.exit("That doesn't look like a valid email address.")

    with _lock:
        existing = find_user_by_email(email)

        if existing:
            if existing.get("role") == "admin":
                answer = input("That account is already an admin. Reset its password? (y/N): ")
                if answer.strip().lower() != "y":
                    sys.exit("Nothing changed.")
                password = getpass.getpass("New password (hidden): ")
                if getpass.getpass("Confirm new password: ") != password:
                    sys.exit("Passwords do not match.")
                if len(password) > MAX_PASSWORD_LENGTH:
                    sys.exit(f"Password must be {MAX_PASSWORD_LENGTH} characters or fewer.")
                missing = [label for label, check in PASSWORD_RULES if not check(password)]
                if missing:
                    sys.exit("Password needs " + ", ".join(missing) + ".")
                update_user_password_hash(existing["id"], generate_password_hash(password))
                print("Admin password reset. You can log in with the new password.")
                return
            answer = input(f'{existing["first_name"]} {existing["last_name"]} is already registered. Make them an admin? (y/N): ')
            if answer.strip().lower() != "y":
                sys.exit("Nothing changed.")
            set_user_role(existing["id"], "admin")
            print("Done. They are now an admin.")
            return

        first = input("First name: ").strip()
        last = input("Last name: ").strip()
        username = input("Username: ").strip()
        birthday_text = input("Birthday (YYYY-MM-DD): ").strip()
        if not NAME_RE.fullmatch(first) or not NAME_RE.fullmatch(last):
            sys.exit("Names may only contain letters, spaces, apostrophes, periods and hyphens.")
        if not USERNAME_RE.fullmatch(username):
            sys.exit("Username may contain letters, numbers, periods, hyphens and underscores.")
        try:
            birthday = date.fromisoformat(birthday_text)
            if birthday > date.today():
                sys.exit("Birthday cannot be in the future.")
        except ValueError:
            sys.exit("Birthday must use YYYY-MM-DD format.")
        if any(u["username"].lower() == username.lower() for u in load_users()):
            sys.exit("That username is already taken.")

        password = getpass.getpass("Password (hidden): ")
        if getpass.getpass("Confirm password: ") != password:
            sys.exit("Passwords do not match.")
        if len(password) > MAX_PASSWORD_LENGTH:
            sys.exit(f"Password must be {MAX_PASSWORD_LENGTH} characters or fewer.")
        missing = [label for label, check in PASSWORD_RULES if not check(password)]
        if missing:
            sys.exit("Password needs " + ", ".join(missing) + ".")

        insert_user(
            {
                "username": username,
                "bday": birthday,
                "first_name": first,
                "last_name": last,
                "mobile": "",
                "email": email,
                "password_hash": generate_password_hash(password),
                "role": "admin",
                "created_at": datetime.now(),
            }
        )
        print("Admin created. You can log in with that email now.")


def reset_password(email=None):
    """Set a fresh password hash for an existing member or admin account."""
    email = (email or input("Account email: ")).strip().lower()
    existing = find_user_by_email(email)
    if not existing:
        sys.exit("No account with that email was found in the configured database.")

    password = getpass.getpass("New password (hidden): ")
    if getpass.getpass("Confirm new password: ") != password:
        sys.exit("Passwords do not match.")
    if len(password) > MAX_PASSWORD_LENGTH:
        sys.exit(f"Password must be {MAX_PASSWORD_LENGTH} characters or fewer.")
    missing = [label for label, check in PASSWORD_RULES if not check(password)]
    if missing:
        sys.exit("Password needs " + ", ".join(missing) + ".")

    update_user_password_hash(existing["id"], generate_password_hash(password))
    print("Password updated. You can log in with the new password.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin()
    elif len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        reset_password(sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        # host="0.0.0.0" lets other devices on your Wi-Fi (like your phone) open the site.
        # The auto-reloader stays on for development, but Flask's interactive debugger is off,
        # because on 0.0.0.0 anyone on the network could reach it.
        app.run(host="0.0.0.0", port=5000, debug=True, use_debugger=False)
