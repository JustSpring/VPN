import os
import gc
import sqlite3
import logging
from datetime import datetime
import base64
import hashlib
import keyring
import pyotp
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logging
logging.basicConfig(level=logging.INFO)

# allow imports from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addresses

# --- log.db ---

def initialize_log_database():
    """Create log.db if missing."""
    with sqlite3.connect(Addresses.LOG_DIR) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                time TEXT NOT NULL
            )
        """)
        con.commit()
        logging.info(f"Initialized log.db")


def recreate_log_table():
    """Remove log.db if it exists, then recreate it."""
    if os.path.exists(Addresses.LOG_DIR):
        try:
            os.remove(Addresses.LOG_DIR)
            logging.info(f"[LOG_MANAGER] Deleted log.db")
        except Exception as E:
            logging.error(f"[LOG_MANAGER] Could not delete log.db: {E}")
    else:
        logging.warning(f"[LOG_MANAGER] log.db not found")

    initialize_log_database()


def add_logging(user, action):
    """Insert a new entry into log.db."""
    time_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    try:
        with sqlite3.connect(Addresses.LOG_DIR) as con:
            con.execute(
                "INSERT INTO log (user, action, time) VALUES (?, ?, ?)",
                (user, action, time_str)
            )
            con.commit()
            logging.info(f"Logged '{action}' for {user} at {time_str}")
    except Exception as err:
        logging.error(f"Error adding log entry: {err}")


# --- full_log.db ---
def initialize_full_log_database():
    """Create full_log.db if missing."""
    with sqlite3.connect(Addresses.FULL_LOG_DIR) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS full_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                site TEXT NOT NULL,
                port TEXT NOT NULL,
                protocol TEXT NOT NULL,
                time TEXT NOT NULL
            )
        """)
        con.commit()
        logging.info(f"Initialized full_log.db")


def recreate_full_log_table():
    """Remove full_log.db if it exists, then recreate it."""
    gc.collect()
    if os.path.exists(Addresses.FULL_LOG_DIR):
        try:
            os.remove(Addresses.FULL_LOG_DIR)
            logging.info(f"[LOG_MANAGER] Deleted full_log.db")
        except Exception as E:
            logging.error(f"[LOG_MANAGER] Could not delete full_log.db: {E}")
    else:
        logging.warning(f"[LOG_MANAGER] full_log.db not found")
    initialize_full_log_database()


def add_full_logging(user, site, port, protocol):
    """Insert a new entry into full_log.db."""
    if not user or not site:
        logging.error("[FULL_LOGGING] user or site is null")
        return

    time_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    try:
        with sqlite3.connect(Addresses.FULL_LOG_DIR) as con:
            con.execute(
                "INSERT INTO full_log (user, site, port, protocol, time) VALUES (?, ?, ?, ?, ?)",
                (user, site, port, protocol, time_str)
            )
            con.commit()
    except Exception as E:
        logging.error(f"[FULL_LOGGING] Error adding entry: {E}")


def get_full_logging(amount):
    """Fetch the most recent `amount` entries from full_log.db."""
    try:
        with sqlite3.connect(Addresses.FULL_LOG_DIR) as con:
            cur = con.execute(
                "SELECT user, site FROM full_log ORDER BY time DESC LIMIT ?",
                (amount,)
            )
            return cur.fetchall()
    except Exception as E:
        logging.error(f"[FULL_LOGGING] Error retrieving entries: {E}")
        return []


# --- active_users.db ---
def initialize_active_database():
    """Create active_users.db if missing."""
    with sqlite3.connect(Addresses.ACTIVE_DIR) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS active (
                username TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                cert TEXT NOT NULL,
                proxy TEXT
            )
        """)
        con.commit()
        logging.info(f"Initialized active_users.db")


def delete_active_table():
    """Delete the active_users.db."""
    if os.path.exists(Addresses.ACTIVE_DIR):
        try:
            os.remove(Addresses.ACTIVE_DIR)
            logging.info(f"[ACTIVE_USERS] Deleted active_users.db")
        except Exception as E:
            logging.error(f"[ACTIVE_USERS] Could not delete active_users.db: {E}")
    else:
        logging.warning(f"[ACTIVE_USERS] active_users.db not found")


def add_active_user(username, ip, cert, proxy=None):
    """Insert or update an active user."""
    try:
        with sqlite3.connect(Addresses.ACTIVE_DIR) as con:
            con.execute(
                "INSERT OR REPLACE INTO active (username, ip, cert, proxy) VALUES (?, ?, ?, ?)",
                (username, ip, cert, proxy)
            )
            con.commit()
            logging.info(f"Active user: {username}@{ip}, cert={cert}, proxy={proxy}")
    except sqlite3.OperationalError as err:
        logging.error(f"Error adding/updating user {username}: {err}")


def update_active_proxy(username, proxy):
    """Update the proxy for a given username."""
    try:
        with sqlite3.connect(Addresses.ACTIVE_DIR) as con:
            con.execute(
                "UPDATE active SET proxy = ? WHERE username = ?",
                (proxy, username)
            )
            con.commit()
            logging.info(f"Updated proxy for {username} to {proxy}")
    except sqlite3.OperationalError as err:
        logging.error(f"Error updating proxy for {username}: {err}")


def get_active_proxy(username=None, ip=None, cert=None):
    """Retrieve the proxy for a user identified by username, IP, or cert."""
    if username:
        key, value = "username", username
    elif ip:
        key, value = "ip", ip
    elif cert:
        key, value = "cert", cert
    else:
        return None

    try:
        with sqlite3.connect(Addresses.ACTIVE_DIR) as con:
            cur = con.execute(f"SELECT proxy FROM active WHERE {key} = ?", (value,))
            row = cur.fetchone()
            if row:
                logging.info(f"Proxy for {key}={value}: {row[0]}")
                return row[0]
    except sqlite3.OperationalError as err:
        logging.error(f"Error retrieving proxy for {key}={value}: {err}")

    return None


def get_active_name( ip=None, cert=None):
    """Retrieve the username for a user identified by IP or cert."""
    if ip:
        key, value = "ip", ip
    elif cert:
        key, value = "cert", cert
    else:
        return None

    try:
        with sqlite3.connect(Addresses.ACTIVE_DIR) as con:
            cur = con.execute(f"SELECT username FROM active WHERE {key} = ?", (value,))
            row = cur.fetchone()
            if row:
                return row[0]
            logging.info(f"No username for {key}={value}")
    except sqlite3.OperationalError as err:
        logging.error(f"Error retrieving username for {key}={value}: {err}")

    return None


def get_active_users():
    """Fetch all active users (username, ip, proxy)."""
    try:
        with sqlite3.connect(Addresses.ACTIVE_DIR) as con:
            cur = con.execute("SELECT username, ip, proxy FROM active")
            return cur.fetchall()
    except Exception as err:
        logging.error(f"Error retrieving active users: {err}")
        return []

def delete_active_user_by_ip(ip):
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                DELETE FROM active
                WHERE ip = ?
            """, (ip,))
            con.commit()
            logging.info(f"User {ip} deleted from active users.")
    except sqlite3.OperationalError as e:
        logging.error(f"Error deleting user {ip}: {e}")

def recreate_active_table():
    """Delete and recreate the active users database."""
    delete_active_table()
    initialize_active_database()


# --- users.db ---
def initialize_user_database():
    """Create users.db if missing."""
    with sqlite3.connect(Addresses.USERS_DIR) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                totpKey BLOB,
                certSerial TEXT
            )
        """)
        con.commit()
        logging.info(f"Initialized users.db")


def generate_store_aes_key(username):
    """Generate a random AES key and store it in the system keyring."""
    key = os.urandom(32)
    encoded = base64.b64encode(key).decode()
    keyring.set_password("TOTP_AES_ENCRYPTION", username, encoded)
    return key


def encrypt_totp(aes_key, totp_value):
    """Encrypt a TOTP secret with AES."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(totp_value.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted


def decrypt_totp(aes_key, encrypted_totp):
    """Decrypt a TOTP secret encrypted with AES."""
    iv, ciphertext = encrypted_totp[:16], encrypted_totp[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def add_user(username, password, totp_key, cert_serial):
    """Insert or update a user record in users.db."""
    aes_key = generate_store_aes_key(username)
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    encrypted = encrypt_totp(aes_key, totp_key)

    try:
        with sqlite3.connect(Addresses.USERS_DIR) as con:
            con.execute(
                "INSERT OR REPLACE INTO users (username, password, totpKey, certSerial) VALUES (?, ?, ?, ?)",
                (username, pwd_hash, encrypted, cert_serial)
            )
            con.commit()
            logging.info(f"Stored user {username}")
    except Exception as err:
        logging.error(f"Error storing user {username}: {err}")


def update_user_cert_serial(username, cert_serial):
    """Update a user's certificate serial number."""
    try:
        serial_str = str(cert_serial)
        with sqlite3.connect(Addresses.USERS_DIR) as con:
            con.execute("UPDATE users SET certSerial = ? WHERE username = ?",(serial_str, username))
            con.commit()
            logging.info(f"Updated certSerial for {username}")
    except Exception as err:
        logging.error(f"Error updating certSerial for {username}: {err}")


def get_user_username(cert_serial):
    """Return the username associated with a given certSerial."""
    try:
        with sqlite3.connect(Addresses.USERS_DIR) as con:
            serial_str = str(cert_serial)
            with sqlite3.connect(Addresses.USERS_DIR) as con:
                cur = con.execute("SELECT username FROM users WHERE certSerial = ?",(serial_str,))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as err:
        logging.error(f"Error fetching username for certSerial {cert_serial}: {err}")
        return None


def get_all_users():
    """Get all users (username, password, totpKey)."""
    try:
        with sqlite3.connect(Addresses.USERS_DIR) as con:
            cur = con.execute("SELECT username, password, totpKey FROM users")
            return cur.fetchall()
    except Exception as err:
        logging.error(f"Error fetching all users: {err}")
        return []


def update_user(username, password, totp_key):
    """Update a user's password and TOTP key (identified by username)."""
    try:
        if password and totp_key:
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            with sqlite3.connect(Addresses.USERS_DIR) as con:
                con.execute(
                    "UPDATE users SET password = ?, totpKey = ? WHERE username = ?",
                    (pwd_hash, totp_key, username)
                )
                con.commit()
                logging.info(f"Updated user {username}")
        elif password:
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            with sqlite3.connect(Addresses.USERS_DIR) as con:
                con.execute(
                    "UPDATE users SET password = ? WHERE username = ?",
                    (pwd_hash, username)
                )
                con.commit()
                logging.info(f"Updated user {username}")
        else:
            with sqlite3.connect(Addresses.USERS_DIR) as con:
                con.execute(
                    "UPDATE users SET totpKey = ? WHERE username = ?",
                    (totp_key, username)
                )
                con.commit()
                logging.info(f"Updated user {username}")

    except Exception as err:
        logging.error(f"Error updating user {username}: {err}")


def delete_user(username):
    """Remove a user from users.db (by username)."""
    try:
        with sqlite3.connect(Addresses.USERS_DIR) as con:
            cur = con.execute("DELETE FROM users WHERE username = ?", (username,))
            con.commit()
            return cur.rowcount > 0
    except Exception as err:
        logging.error(f"Error deleting user {username}: {err}")
        return False


def check_user(username, password, totp):
    """Verify credentials and TOTP code. Returns 0 on success, -1 on failure."""
    try:
        encoded = keyring.get_password("TOTP_AES_ENCRYPTION", username)
        if not encoded:
            raise ValueError(f"No AES key for {username}")

        aes_key = base64.b64decode(encoded)
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()

        with sqlite3.connect(Addresses.USERS_DIR) as con:
            cur = con.execute(
                "SELECT totpKey, certSerial FROM users WHERE username = ? AND password = ?",
                (username, pwd_hash)
            )
            row = cur.fetchone()
            if not row or pyotp.TOTP(decrypt_totp(aes_key, row[0])).now() != totp:
                return -1

            logging.info(f"Authenticated {username}, cert={row[1]}")
            return 0
    except Exception as err:
        logging.error(f"Error in check_user: {err}")
        return -1


def create():
    """Initialize all databases."""
    initialize_user_database()
    initialize_log_database()
    initialize_full_log_database()

