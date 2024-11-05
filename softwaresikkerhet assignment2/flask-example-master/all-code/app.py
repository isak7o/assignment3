import os
import sqlite3
import bcrypt
import datetime
import hashlib
import pyotp
import qrcode
from io import BytesIO
from base64 import b64encode
from flask import Flask, session, url_for, redirect, render_template, request, jsonify, flash
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.utils import secure_filename
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from database2 import (
    list_users, verify_user, delete_user_from_db, add_user, increment_login_attempts,
    reset_login_attempts, check_account_lock, set_two_factor_secret, get_two_factor_secret,
    read_note_from_db, write_note_into_db, delete_note_from_db, match_user_id_with_note_id,
    image_upload_record, list_images_for_user, match_user_id_with_image_uid, delete_image_from_db
)

app = Flask(__name__)
app.config.from_object('config')
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)


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


# Login endpoint with brute-force protection
@app.route('/login', methods=['GET', 'POST'])
def FUN_login():
    if request.method == 'GET':
        return redirect(url_for('FUN_root'))  # Redirect if accessed directly via GET

    # Handle POST request for login form submission
    username = request.form.get('id')
    password = request.form.get('pw')

    if not username or not password:
        flash("Username and password are required", "danger")
        return redirect(url_for("FUN_root"))

    if check_account_lock(username):
        flash("Account is locked due to too many failed attempts", "danger")
        return redirect(url_for("FUN_root"))

    user = verify_user(username=username, password=password)
    if user:
        reset_login_attempts(username)
        session['current_user'] = username

        # Check if 2FA is enabled for this user
        if get_two_factor_secret(username):
            # Redirect to verify 2FA page
            return redirect(url_for("verify_2fa"))
        else:
            # No 2FA, proceed to the home page
            flash("Login successful", "success")
            return redirect(url_for("FUN_root"))
    else:
        increment_login_attempts(username)
        flash("Invalid username or password", "danger")
        return redirect(url_for("FUN_root"))  # Redirect back to root page on failure



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
# Root route
@app.route("/")
def FUN_root():
    # Check if the user is logged in
    if 'current_user' in session and session.get('2fa_verified'):
        # User is logged in and 2FA is verified, load their posts
        posts = read_note_from_db(session['current_user'])
        return render_template("index.html", posts=posts, user=session['current_user'])
    else:
        # User is not logged in or 2FA is not verified, load public posts or a generic homepage
        posts = read_note_from_db('public')  # Load public posts or a generic view
        return render_template("index.html", posts=posts, user=None)


# New post route
@app.route("/new", methods=["GET", "POST"])
@login_required
def new_post():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")

        # Save the post to the database using the current user's session
        write_note_into_db(session['current_user'], f"{title}: {content}")
        flash("New post created successfully", "success")
        return redirect(url_for("FUN_root"))  # Redirect to homepage after successful post creation

    return render_template("new_post.html")


@app.route("/public")
def FUN_public():
    return render_template("public_page.html")

# Private route
@app.route("/private/")
@login_required
def FUN_private():
    notes_list = read_note_from_db(session['current_user'])
    notes_table = zip(
        [x[0] for x in notes_list],
        [x[1] for x in notes_list],
        [x[2] for x in notes_list],
        ["/delete_note/" + x[0] for x in notes_list]
    )
    images_list = list_images_for_user(session['current_user'])
    images_table = zip(
        [x[0] for x in images_list],
        [x[1] for x in images_list],
        [x[2] for x in images_list],
        ["/delete_image/" + x[0] for x in images_list]
    )
    return render_template("private_page.html", notes=notes_table, images=images_table)

# File upload configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Image upload route
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

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
