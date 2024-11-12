import os
import sqlite3
import uuid

import bcrypt
import datetime

import bleach
from astropy.utils.data import import_file_to_cache
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, url_for, session
import hashlib
import pyotp
import qrcode
import logging
from io import BytesIO
from base64 import b64encode
from flask import Flask, session, url_for, redirect, render_template, request, jsonify, flash
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.utils import secure_filename
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from uuid import uuid4
from functools import wraps
from database2 import (
    list_users, verify_user, delete_user_from_db, add_user, increment_login_attempts,
    reset_login_attempts, check_account_lock, set_two_factor_secret, get_two_factor_secret,
    read_note_from_db, write_note_into_db, delete_note_from_db, match_user_id_with_note_id,
    image_upload_record, list_images_for_user, match_user_id_with_image_uid, delete_image_from_db, get_user_by_username,
    users_table
)
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

app = Flask(__name__)
app.config.from_object('config')
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)

# Koble til databasen
conn = sqlite3.connect('database_file/notes.db')
cursor = conn.cursor()

# Hent og rens alle innlegg
cursor.execute("SELECT note_id, note FROM notes")
notes = cursor.fetchall()

for note_id, note in notes:
    # Rens innholdet og oppdater databasen
    clean_note = bleach.clean(note)
    cursor.execute("UPDATE notes SET note = ? WHERE note_id = ?", (clean_note, note_id))

conn.commit()
conn.close()



# Initialize OAuth
oauth = OAuth(app)
oauth.register(
    name="github",
    client_id=app.config["OAUTH2_CLIENT_ID"],
    client_secret=app.config["OAUTH2_CLIENT_SECRET"],
    authorize_url="https://github.com/login/oauth/authorize",
    access_token_url="https://github.com/login/oauth/access_token",
    client_kwargs={"scope": "user:email"},
)

# Secure session configuration
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Enhanced login_required decorator with 2FA check
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'current_user' not in session:
            return redirect(url_for('FUN_login'))
        if not session.get('2fa_verified') and request.endpoint != 'setup_2fa':
            return redirect(url_for('setup_2fa'))
        return f(*args, **kwargs)
    return decorated_function

# 2FA setup route
@app.route("/setup_2fa")
def setup_2fa():
    if 'current_user' not in session:
        return redirect(url_for('FUN_login'))  # Redirect to login if not logged in

    user_id = session['current_user']
    totp_secret = pyotp.random_base32()
    set_two_factor_secret(user_id, totp_secret)

    # Generate QR code data for Google Authenticator
    totp = pyotp.TOTP(totp_secret)
    qr_url = totp.provisioning_uri(name=user_id, issuer_name="YourAppName")

    # Create the QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_url)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")

    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = b64encode(buf.getvalue()).decode("utf-8")

    # Render the 2FA setup page with the QR code
    return render_template("setup_2fa.html", qr_data=qr_b64)

# OAuth2 Login Route

@app.route("/login/oauth")
def login_oauth():
    redirect_uri = url_for("auth_callback", _external=True)
    state = str(uuid4())  # Generer en tilfeldig state
    session['oauth_state'] = state  # Lagre state i session for å sammenligne senere
    return oauth.github.authorize_redirect(redirect_uri, state=state)


# OAuth2 Callback Route
@app.route("/auth/callback")
def auth_callback():
    # Verify that the state matches
    request_state = request.args.get('state')
    session_state = session.pop('oauth_state', None)

    if session_state != request_state:
        flash("CSRF Warning! State not equal in request and response.", "danger")
        return redirect(url_for("FUN_root"))

    # Get the token
    token = oauth.github.authorize_access_token()
    # Fetch user information
    user_info = oauth.github.get("https://api.github.com/user").json()

    # Extract user details
    email = user_info.get("email")
    username = user_info.get("login")

    # Check if the user already exists in the database
    existing_user = get_user_by_username(username=username)
    if not existing_user:
        # Add new user to database
        add_user(username=username, password=None, email=email)

    # Store user in session and mark as authenticated
    session["current_user"] = username
    session["2fa_verified"] = True  # Assuming OAuth bypasses 2FA for simplicity

    return redirect(url_for("FUN_root"))  # Redirect to homepage



# 2FA verification route
@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if request.method == "GET":
        # Display the verification form
        return render_template("verify_2fa.html")

    # POST request: Process the verification code
    if 'current_user' not in session:
        return redirect(url_for('FUN_login'))  # Redirect to login if not logged in

    user_id = session['current_user']
    totp_code = request.form.get("totp_code")
    totp_secret = get_two_factor_secret(user_id)

    if not totp_secret:
        flash("2FA not set up correctly. Please try again.", "danger")
        return redirect(url_for("setup_2fa"))

    # Initialize the TOTP with the user's secret
    totp = pyotp.TOTP(totp_secret)

    # Verify the code using `totp.verify()`
    if totp.verify(totp_code):
        session['2fa_verified'] = True  # Mark 2FA as verified in the session
        flash("2FA verification successful!", "success")
        return redirect(url_for("FUN_root"))  # Redirect to the main page
    else:
        flash("Invalid 2FA code. Please try again.", "danger")
        return redirect(url_for("verify_2fa"))

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")  # Show registration form if accessed via GET

    # Handle registration form submission (POST)
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')

    if not username or not password or not email:
        flash("All fields are required", "danger")
        return redirect(url_for("register"))

    try:
        # Add the user to the database
        add_user(username=username, password=password, email=email)

        # Log the user in immediately by setting the session
        session['current_user'] = username
        session['2fa_verified'] = False  # Mark as not verified for 2FA

        # Redirect to 2FA setup page right after registration
        return redirect(url_for('setup_2fa'))

    except SQLAlchemyError:
        flash("Username or email already exists", "danger")
        return redirect(url_for("register"))


@app.route('/login', methods=['POST'])
def FUN_login():
    # Kontroller om forespørselen er en POST-forespørsel
    if request.method == 'POST':
        username = request.form.get('id')
        password = request.form.get('pw')
        totp_code = request.form.get('totp_code')

        # Valider at brukernavn og passord er fylt ut
        if not username or not password:
            flash("Username and password are required", "danger")
            return redirect(url_for("FUN_root"))

        # Sjekk om kontoen er låst
        if check_account_lock(username):
            flash("Account is locked due to too many failed attempts. Try again later.", "danger")
            return redirect(url_for("FUN_root"))

        # Verifiser brukeren med brukernavn og passord
        user = verify_user(username, password)
        if user:
            # Tilbakestill antall mislykkede forsøk hvis innloggingen er vellykket
            reset_login_attempts(username)
            session['current_user'] = username

            # Hvis brukeren har aktivert 2FA, bekreft TOTP-koden
            totp_secret = get_two_factor_secret(username)
            if totp_secret:
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(totp_code):
                    flash("Invalid 2FA code. Please try again.", "danger")
                    return redirect(url_for("FUN_root"))

            # Markér brukeren som autentisert med 2FA
            session['2fa_verified'] = True
            flash("Login successful", "success")
            return redirect(url_for("FUN_root"))

        else:
            # Øk antallet mislykkede forsøk ved feil brukernavn/passord
            increment_login_attempts(username)

            # Sjekk om kontoen nå er låst etter mislykket forsøk
            if check_account_lock(username):
                flash("Account is locked due to too many failed attempts. Try again later.", "danger")
            else:
                flash("Invalid username or password", "danger")

            return redirect(url_for("FUN_root"))

    return redirect(url_for("FUN_root"))


# Error handlers
@app.errorhandler(401)
def FUN_401(error):
    return render_template("page_401.html"), 401

@app.errorhandler(403)
def FUN_403(error):
    return render_template("page_403.html"), 403

# Logout
@app.route("/logout/")
def FUN_logout():
    session.pop("current_user", None)
    session.pop("2fa_verified", None)  # Clear 2FA verified flag
    return redirect(url_for("FUN_root"))

# Root route
@app.route("/")
def FUN_root():
    # Hent alle innlegg fra databasen
    all_posts = read_note_from_db()

    # Sjekk om brukeren er logget inn
    if 'current_user' in session and session.get('2fa_verified'):
        return render_template("index.html", posts=all_posts)
    else:
        return render_template("index.html", posts=all_posts)


# New post route
@app.route("/new", methods=["GET", "POST"])
@login_required
def new_post():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        if title and content:
            # Lagre innlegget i databasen ved å bruke den oppdaterte funksjonen
            write_note_into_db(session['current_user'], f"{title}: {content}")
            flash("New post created successfully", "success")
        else:
            flash("Both title and content are required", "danger")
        return redirect(url_for("FUN_root"))  # Redirect til hovedsiden etter å ha lagret innlegget

    return render_template("new_post.html")

@app.route("/public")
def FUN_public():
    return render_template("public_page.html")

# Image upload route
def allowed_file(filename):
    pass


@app.route("/upload_image", methods=['POST'])
@login_required
def FUN_upload_image():
    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        flash('No file selected or file type not allowed', category='danger')
        return redirect(url_for("FUN_private"))

    filename = secure_filename(file.filename)
    upload_time = str(datetime.datetime.now())
    image_uid = hashlib.sha1((upload_time + filename).encode()).hexdigest()
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_uid + "-" + filename))
    image_upload_record(image_uid, session['current_user'], filename, upload_time)
    return redirect(url_for("FUN_private"))

def read_note_from_db(user_id=None):
    try:
        conn = sqlite3.connect('database_file/notes.db')
        cursor = conn.cursor()

        if user_id:
            cursor.execute("SELECT note_id, note, timestamp FROM notes WHERE user = ?", (user_id,))
        else:
            cursor.execute("SELECT note_id, note, timestamp, user FROM notes")

        notes = cursor.fetchall()
        conn.close()
        return notes
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        return []


def list_users():
    result = session.execute(users_table.select()).fetchall()
    print(result)
    return [row.username for row in result]


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
