from app import ph, encrypt_data, execute_query
import pyotp

username = "admin"
email = "flirtycoding3@gmail.com"
password = "Code@2006.ton"
role = "admin"

# Hash the password
password_hash = ph.hash(password)

# Generate and encrypt MFA secret
mfa_secret = pyotp.random_base32()
encrypted_mfa_secret = encrypt_data(mfa_secret)

# Insert admin user
user_id = execute_query(
    """INSERT INTO users (username, email, password_hash, role, mfa_enabled, mfa_secret)
       VALUES (%s, %s, %s, %s, %s, %s)""",
    (username, email, password_hash, role, 0, encrypted_mfa_secret)
)
print(f"Admin user created with user_id: {user_id}") 