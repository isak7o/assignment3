# config.py
import os

SECRET_KEY = 'your_secret_key'
UPLOAD_FOLDER = "image_pool"
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
WTF_CSRF_ENABLED = True

SQLALCHEMY_ECHO = False
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_DATABASE_URI = 'sqlite:///database_file/users.db'



# GitHub OAuth configuration
OAUTH2_CLIENT_ID = "Ov23likfD54jPiv6kHDg"  # Replace with your GitHub Client ID
OAUTH2_CLIENT_SECRET = "70fa9a0e13dff1a01c256994daf37d3506c2ba3f"  # Replace with your GitHub Client Secret
OAUTH2_REDIRECT_URI = "http://127.0.0.1:5000/auth/callback"
