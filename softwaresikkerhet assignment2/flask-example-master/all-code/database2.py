import os
import bcrypt
import datetime
import uuid
from sqlalchemy import create_engine, Table, MetaData, Column, String, Integer, DateTime, Boolean, text
from sqlalchemy.orm import sessionmaker

# Setup database connection
def get_engine():
    env = os.getenv("ENVIRONMENT", "development")
    if env == "development":
        database_uri = 'sqlite:///database_file/users.db'
    elif env == "production":
        db_username = os.getenv('POSTGRES_USER')
        db_password = os.getenv('POSTGRES_PASSWORD')
        db_host = os.getenv('POSTGRES_HOST')
        db_name = os.getenv('POSTGRES_DB')
        database_uri = f'postgresql://{db_username}:{db_password}@{db_host}/{db_name}'
    return create_engine(database_uri, echo=True)

engine = get_engine()
metadata = MetaData()
Session = sessionmaker(bind=engine)
session = Session()

# Define the users table with updated schema
users_table = Table('users', metadata,
    Column('id', String, primary_key=True),          # Unique identifier
    Column('username', String, unique=True),         # Username for login
    Column('password_hash', String),                 # Hashed password
    Column('email', String, unique=True),            # Email for 2FA and notifications
    Column('two_factor_secret', String, nullable=True),  # TOTP secret for 2FA
    Column('login_attempts', Integer, default=0),    # Track failed login attempts
    Column('lock_until', DateTime, nullable=True),   # Lockout time after failed attempts
    Column('created_at', DateTime, default=datetime.datetime.utcnow),  # Account creation time
    Column('is_active', Boolean, default=True)       # Account status
)

# Define the notes table
notes_table = Table('notes', metadata,
    Column('user', String),
    Column('timestamp', String),
    Column('note', String),
    Column('note_id', String, primary_key=True)
)

# Define the images table
images_table = Table('images', metadata,
    Column('uid', String, primary_key=True),
    Column('owner', String),
    Column('name', String),
    Column('timestamp', String)
)

# Create the tables in the database
metadata.create_all(engine)

# Functions for user operations
def add_user(username, password, email):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = {
        'id': str(uuid.uuid4()),
        'username': username,
        'password_hash': password_hash,
        'email': email,
        'created_at': datetime.datetime.utcnow(),
        'is_active': True  # Set default value
    }
    session.execute(users_table.insert().values(new_user))
    session.commit()

def verify_user(username, password):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return user
    return None

def increment_login_attempts(username):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()
    if user:
        login_attempts = user.login_attempts + 1
        lock_until = user.lock_until
        if login_attempts >= 3:
            lock_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        session.execute(users_table.update().where(users_table.c.username == username).values(
            login_attempts=login_attempts, lock_until=lock_until))
        session.commit()

def reset_login_attempts(username):
    session.execute(users_table.update().where(users_table.c.username == username).values(
        login_attempts=0, lock_until=None))
    session.commit()

def check_account_lock(username):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()
    if user and user.lock_until and user.lock_until > datetime.datetime.utcnow():
        return True
    return False

def set_two_factor_secret(username, secret):
    session.execute(users_table.update().where(users_table.c.username == username).values(
        two_factor_secret=secret))
    session.commit()

def get_two_factor_secret(username):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()
    return user.two_factor_secret if user else None

# Additional helper functions to match previous app.py usage

def list_users():
    result = session.execute(users_table.select())
    return [row.username for row in result]

def delete_user_from_db(username):
    session.execute(users_table.delete().where(users_table.c.username == username))
    session.execute(notes_table.delete().where(notes_table.c.user == username))
    session.execute(images_table.delete().where(images_table.c.owner == username))
    session.commit()

def match_user_id_with_note_id(note_id):
    note = session.execute(notes_table.select().where(notes_table.c.note_id == note_id)).fetchone()
    return note.user if note else None

def match_user_id_with_image_uid(image_uid):
    image = session.execute(images_table.select().where(images_table.c.uid == image_uid)).fetchone()
    return image.owner if image else None

# Functions for notes management
def read_note_from_db(user):
    result = session.execute(notes_table.select().where(notes_table.c.user == user)).fetchall()
    return result

def write_note_into_db(user, note_to_write):
    note_id = str(uuid.uuid4())
    current_timestamp = str(datetime.datetime.now())
    new_note = {
        'user': user,
        'timestamp': current_timestamp,
        'note': note_to_write,
        'note_id': note_id
    }
    session.execute(notes_table.insert().values(new_note))
    session.commit()

def delete_note_from_db(note_id):
    session.execute(notes_table.delete().where(notes_table.c.note_id == note_id))
    session.commit()

# Functions for images management
def image_upload_record(uid, owner, image_name, timestamp):
    session.execute(images_table.insert().values(uid=uid, owner=owner, name=image_name, timestamp=timestamp))
    session.commit()

def list_images_for_user(owner):
    result = session.execute(images_table.select().where(images_table.c.owner == owner)).fetchall()
    return result

def delete_image_from_db(image_uid):
    session.execute(images_table.delete().where(images_table.c.uid == image_uid))
    session.commit()

if __name__ == "__main__":
    print("Database setup completed with user, notes, and images tables.")
