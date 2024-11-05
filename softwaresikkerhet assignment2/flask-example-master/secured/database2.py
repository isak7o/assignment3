import os
import datetime
import hashlib
from sqlalchemy import create_engine, Table, MetaData, Column, String, inspect, text
from sqlalchemy.orm import sessionmaker, scoped_session

# Setup database connection
def get_engine():
    env = os.getenv("ENVIRONMENT", "development")
    if env == "development":
        database_uri = 'sqlite:///database_file/tree.db'
    elif env == "production":
        db_username = os.getenv('POSTGRES_USER')
        db_password = os.getenv('POSTGRES_PASSWORD')
        db_host = os.getenv('POSTGRES_HOST')
        db_name = os.getenv('POSTGRES_DB')
        database_uri = f'postgresql://{db_username}:{db_password}@{db_host}/{db_name}'
    return create_engine(database_uri, echo=True)

engine = get_engine()
metadata = MetaData()
metadata.bind = engine
Session = sessionmaker(bind=engine)
print("Database type:", engine.dialect.name)
inspector = inspect(engine)
tables = inspector.get_table_names()

# Define the tables (if they don't exist)
if 'users' not in tables:
    users_table = Table('users', metadata,
                        Column('id', String, primary_key=True),
                        Column('pw', String))
    print("Users table defined")

if 'notes' not in tables:
    notes_table = Table('notes', metadata,
                        Column('user', String),
                        Column('timestamp', String),
                        Column('note', String),
                        Column('note_id', String, primary_key=True))
    print("Notes table defined")

if 'images' not in tables:
    images_table = Table('images', metadata,
                         Column('uid', String, primary_key=True),
                         Column('owner', String),
                         Column('name', String),
                         Column('timestamp', String))
    print("Images table defined")

# Create the tables in the database
metadata.create_all(engine)
print("Tables created")

# Insert some data into the tables
with engine.begin() as conn:
    if 'users' not in tables:
        conn.execute(users_table.insert(), [
            {'id': 'ADMIN', 'pw': '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'},
            {'id': 'TEST', 'pw': '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92'}
        ])
    if 'notes' not in tables:
        conn.execute(images_table.insert(), [
            {'uid': '3afadaa2a3cbc1fffc6d8229ca1936b9760e1c56', 'owner': 'TEST', 'name': 'made-with-flask.png',
             'timestamp': '2017-07-08 10:49:19.018804'},
            {'uid': 'f739cc0a8bc1c3d17cc3dcc4fc5ff70b8266998b', 'owner': 'TEST', 'name': 'flask-project.png',
             'timestamp': '2017-07-08 10:57:45.759152'},
            {'uid': 'cbebc37b8e9ae56d722fc3966bb78da4ce48f9a6', 'owner': 'ADMIN', 'name': 'flask.png',
             'timestamp': '2017-07-08 11:37:04.630910'}
        ])
    if 'images' not in tables:
        conn.execute(notes_table.insert(), [
            {'user': 'TEST', 'timestamp': '2017-07-03 22:22:03.301170', 'note': 'This is a note of user TEST.',
             'note_id': '1e3acedb82a9d9bdbd75723a3ea215059159fc21'},
            {'user': 'ADMIN', 'timestamp': '2017-07-03 22:22:18.457563', 'note': 'This is a note of user ADMIN.',
             'note_id': '1f90a08ac4e231db43a20905adf448dd42482230'}
        ])

# Database operations
def list_users():
    session = Session()
    result = session.execute(text("SELECT id FROM users;"))
    users = [row[0] for row in result]
    session.close()
    return users

def verify(id, pw):
    session = Session()
    query = text("SELECT pw FROM users WHERE id = :id;")
    result = session.execute(query, {'id': id}).fetchone()
    session.close()
    if result:
        stored_pw = result[0]
        return stored_pw == hashlib.sha256(pw.encode()).hexdigest()
    return False

def add_user(id, pw):
    session = Session()
    hashed_pw = hashlib.sha256(pw.encode()).hexdigest()
    query = text("INSERT INTO users (id, pw) VALUES (:id, :pw);")
    session.execute(query, {'id': id.upper(), 'pw': hashed_pw})
    session.commit()
    session.close()

def delete_user_from_db(id):
    session = Session()
    session.execute(text("DELETE FROM users WHERE id = :id;"), {'id': id})
    session.execute(text("DELETE FROM notes WHERE user = :user;"), {'user': id})
    session.execute(text("DELETE FROM images WHERE owner = :owner;"), {'owner': id})
    session.commit()
    session.close()

def read_note_from_db(id):
    session = Session()
    query = text("SELECT note_id, timestamp, note FROM notes WHERE user = :user;")
    result = session.execute(query, {'user': id.upper()})
    notes = result.fetchall()
    session.close()
    return notes

def write_note_into_db(id, note_to_write):
    session = Session()
    current_timestamp = str(datetime.datetime.now())
    note_id = hashlib.sha1((id.upper() + current_timestamp).encode()).hexdigest()
    query = text("INSERT INTO notes (user, timestamp, note, note_id) VALUES (:user, :timestamp, :note, :note_id);")
    session.execute(query, {'user': id.upper(), 'timestamp': current_timestamp, 'note': note_to_write, 'note_id': note_id})
    session.commit()
    session.close()

def delete_note_from_db(note_id):
    session = Session()
    session.execute(text("DELETE FROM notes WHERE note_id = :note_id;"), {'note_id': note_id})
    session.commit()
    session.close()

def image_upload_record(uid, owner, image_name, timestamp):
    session = Session()
    query = text("INSERT INTO images (uid, owner, name, timestamp) VALUES (:uid, :owner, :name, :timestamp);")
    session.execute(query, {'uid': uid, 'owner': owner, 'name': image_name, 'timestamp': timestamp})
    session.commit()
    session.close()

def list_images_for_user(owner):
    session = Session()
    query = text("SELECT uid, timestamp, name FROM images WHERE owner = :owner;")
    result = session.execute(query, {'owner': owner})
    images = result.fetchall()
    session.close()
    return images

def match_user_id_with_note_id(note_id):
    session = Session()
    query = text("SELECT user FROM notes WHERE note_id = :note_id;")
    result = session.execute(query, {'note_id': note_id}).fetchone()
    session.close()
    if result:
        return result[0]
    return None

def match_user_id_with_image_uid(image_uid):
    session = Session()
    query = text("SELECT owner FROM images WHERE uid = :uid;")
    result = session.execute(query, {'uid': image_uid}).fetchone()
    session.close()
    if result:
        return result[0]
    return None

def delete_image_from_db(image_uid):
    session = Session()
    session.execute(text("DELETE FROM images WHERE uid = :uid;"), {'uid': image_uid})
    session.commit()
    session.close()

if __name__ == "__main__":
    print(list_users())