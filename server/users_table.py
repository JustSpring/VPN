import base64
import os
import sqlite3
import hashlib
import pyotp
import keyring
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

logging.basicConfig(level=logging.INFO)

# Initialize the database
def initialize_database():
    with sqlite3.connect("users.db") as con:
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                gotKey BOOL,
                totpKey BLOB,
                certSerial TEXT
            )
        """)
        con.commit()
        logging.info("Database initialized.")

def generate_store_aes_key(username):
    key = os.urandom(32)
    keyring.set_password("TOTP_AES_ENCRYPTION", username, base64.b64encode(key).decode("utf-8"))
    return key

def add_user(username, password, totp_key, cert_serial, got_key=False):
    aes_key = generate_store_aes_key(username)
    password_sha256 = hashlib.sha256(password.encode()).hexdigest()
    encrypted_totp = encrypt_totp(aes_key, totp_key)
    with sqlite3.connect("users.db") as con:
        cur = con.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO users (username, password, gotKey, totpKey, certSerial)
            VALUES (?, ?, ?, ?, ?)
        """, (username, password_sha256, got_key, encrypted_totp, cert_serial))
        con.commit()
        logging.info(f"User {username} added/updated.")

def update_cert_serial(username, cert_serial):
    try:
        with sqlite3.connect("users.db") as con:
            cur = con.cursor()
            cur.execute("""
                UPDATE users
                SET certSerial = ?
                WHERE username = ?
            """, (str(cert_serial), username))
            con.commit()
            logging.info(f"Certificate serial number updated for user {username}.")
    except Exception as e:
        logging.error(f"Error updating certificate serial number for {username}: {e}")

def get_username(cert_serial):
    try:
        with sqlite3.connect("users.db") as con:
            cur = con.cursor()
            cur.execute("""
                SELECT username
                FROM users
                WHERE certSerial = ?
            """, (str(cert_serial),))
            result = cur.fetchone()
            if result:
                logging.info(f"Found username '{result[0]}' for certSerial '{cert_serial}'.")
                return result[0]
            else:
                logging.info(f"No username found for certSerial '{cert_serial}'.")
                return None
    except Exception as e:
        logging.error(f"Error retrieving username for certSerial '{cert_serial}': {e}")
        return None

def encrypt_totp(aes_key, totp_value):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(totp_value.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_totp = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_totp

def decrypt_totp(aes_key, encrypted_totp):
    iv = encrypted_totp[:16]
    ciphertext = encrypted_totp[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_totp = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_totp = unpadder.update(decrypted_padded_totp) + unpadder.finalize()
    return decrypted_totp.decode()

def check_user(username, password, totp):
    try:
        encoded_aes_key = keyring.get_password("TOTP_AES_ENCRYPTION", username)
        if not encoded_aes_key:
            raise ValueError(f"No AES key found for user: {username}")
        aes_key = base64.b64decode(encoded_aes_key)
        with sqlite3.connect("users.db") as con:
            cur = con.cursor()
            cur.execute("""
                SELECT username, password, gotKey, totpKey, certSerial
                FROM users
                WHERE username = ? AND password = ?
            """, (username, hashlib.sha256(password.encode()).hexdigest()))
            user = cur.fetchone()
            if not user:
                return -1
            decrypted_totp = decrypt_totp(aes_key, user[3])
            totp_server = pyotp.TOTP(decrypted_totp)
            if totp_server.now() != totp:
                return -1
            logging.info(f"Certificate serial number: {user[4]}")
            return user[2]
    except Exception as e:
        logging.error(f"Error in check_user: {e}")
        return -1

if __name__ == "__main__":
    initialize_database()

    # Test code
    key = pyotp.random_base32()
    cert_serial = "1234567890"
    add_user("aviv", "12345678", key, cert_serial)
    print(get_username(cert_serial))

    totp = pyotp.TOTP(key)
    print(check_user("aviv", "12345678", totp.now()))
