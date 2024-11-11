import bcrypt

# Replace with the actual password hash from your database
stored_hash = "$2b$12$vUkU9jN2pglKo89aTwQ51uMbAvP0jomY7NSZdUOcLNVWyRm.TtwRm"  # Example hash
password_attempt = "AdminAdmin1!"  # Replace with the password you want to test

# Verify if the password matches the stored hash
if bcrypt.checkpw(password_attempt.encode('utf-8'), stored_hash.encode('utf-8')):
    print("Password matches")
else:
    print("Password does not match")
