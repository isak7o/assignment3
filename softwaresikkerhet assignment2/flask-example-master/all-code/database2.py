import os
import sqlite3

import bcrypt
import datetime
import uuid

from flask import flash
from sqlalchemy import create_engine, Table, MetaData, Column, String, Integer, DateTime, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session

# Setup database connection
def get_engine():
    env = os.getenv("ENVIRONMENT", "development")
    if env == "development":
        database_uri = 'sqlite:///database_file/users.db'
        return create_engine(database_uri, echo=True, connect_args={'check_same_thread': False})
    elif env == "production":
        db_username = os.getenv('POSTGRES_USER')
        db_password = os.getenv('POSTGRES_PASSWORD')
        db_host = os.getenv('POSTGRES_HOST')
        db_name = os.getenv('POSTGRES_DB')
        database_uri = f'postgresql://{db_username}:{db_password}@{db_host}/{db_name}'
        return create_engine(database_uri, echo=True)


engine = get_engine()
metadata = MetaData()
Session = scoped_session(sessionmaker(bind=engine))
session = Session()

# Define the users table
users_table = Table('users', metadata,
    Column('id', String, primary_key=True),
    Column('username', String, unique=True),
    Column('password_hash', String),
    Column('email', String, unique=True),
    Column('two_factor_secret', String, nullable=True),
    Column('login_attempts', Integer, default=0),
    Column('lock_until', DateTime, nullable=True),
    Column('created_at', DateTime, default=datetime.datetime.utcnow),
    Column('is_active', Boolean, default=True)
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

# User functions
def add_user(username, password=None, email=None):
    if password:
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        password_hash = None

    new_user = {
        'id': str(uuid.uuid4()),
        'username': username,
        'password_hash': password_hash,
        'email': email,
        'created_at': datetime.datetime.utcnow(),
        'is_active': True
    }
    session.execute(users_table.insert().values(new_user))
    session.commit()

def verify_user(username, password):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()

    if user:
        print(f"User found: {user.username}")  # Debugging output
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            print("Password verified successfully.")  # Debugging output
            return user
        else:
            print("Password verification failed.")  # Debugging output
    else:
        print("User not found.")  # Debugging output

    return None


def increment_login_attempts(username):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()
    if user:
        login_attempts = user.login_attempts + 1
        lock_until = user.lock_until

        # Hvis antall forsøk er 3 eller mer, lås kontoen i 5 minutter
        if login_attempts >= 3:
            lock_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
            flash(f"Account locked due to too many failed attempts. Locked until {lock_until}.", "danger")

        session.execute(users_table.update().where(users_table.c.username == username).values(
            login_attempts=login_attempts, lock_until=lock_until))
        session.commit()


def reset_login_attempts(username):
    session.execute(users_table.update().where(users_table.c.username == username).values(
        login_attempts=0, lock_until=None))
    session.commit()


def check_account_lock(username):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()
    if user and user.lock_until:
        if user.lock_until > datetime.datetime.utcnow():
            return True  # Kontoen er fortsatt låst
        else:
            # Lås er utløpt, tilbakestill antall forsøk
            reset_login_attempts(username)
    return False


def set_two_factor_secret(username, secret):
    session.execute(users_table.update().where(users_table.c.username == username).values(
        two_factor_secret=secret))
    session.commit()

def get_two_factor_secret(username):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()
    return user.two_factor_secret if user else None

def list_users():
    result = session.execute(users_table.select())
    return [row.username for row in result]

def delete_user_from_db(username):
    session.execute(users_table.delete().where(users_table.c.username == username))
    session.execute(notes_table.delete().where(notes_table.c.user == username))
    session.execute(images_table.delete().where(images_table.c.owner == username))
    session.commit()

def get_user_by_username(username):
    user = session.execute(users_table.select().where(users_table.c.username == username)).fetchone()
    return user

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


def delete_note_from_db(note_id):
    session.execute(notes_table.delete().where(notes_table.c.note_id == note_id))
    session.commit()

# Images functions
def image_upload_record(uid, owner, image_name, timestamp):
    session.execute(images_table.insert().values(uid=uid, owner=owner, name=image_name, timestamp=timestamp))
    session.commit()

def list_images_for_user(owner):
    result = session.execute(images_table.select().where(images_table.c.owner == owner)).fetchall()
    return result

def delete_image_from_db(image_uid):
    session.execute(images_table.delete().where(images_table.c.uid == image_uid))
    session.commit()

def match_user_id_with_note_id(note_id):
    note = session.execute(notes_table.select().where(notes_table.c.note_id == note_id)).fetchone()
    return note.user if note else None

def match_user_id_with_image_uid(image_uid):
    image = session.execute(images_table.select().where(images_table.c.uid == image_uid)).fetchone()
    return image.owner if image else None
def write_note_into_db(user, note):
    try:
        # Koble til databasen
        conn = sqlite3.connect('database_file/notes.db')
        cursor = conn.cursor()

        # Generer en unik ID for notatet
        note_id = str(uuid.uuid4())
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        # Opprett tabellen hvis den ikke eksisterer
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                user TEXT,
                note_id TEXT PRIMARY KEY,
                note TEXT,
                timestamp TEXT
            )
        """)

        # Sett inn notatet i databasen
        cursor.execute(
            "INSERT INTO notes (user, note_id, note, timestamp) VALUES (?, ?, ?, ?)",
            (user, note_id, note, timestamp)
        )

        # Lagre endringene og lukk tilkoblingen
        conn.commit()
        conn.close()
        print("Note successfully saved")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

if __name__ == "__main__":
    print("Database setup completed with user, notes, and images tables.")
