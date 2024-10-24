import base64
import os
import sqlite3
import hashlib
import pyotp
import keyring
import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

con = sqlite3.connect("users.db")
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT, gotKey BOOL, totpKey)")
def generate_store_aes_key(username):
    key= os.urandom(32)
    keyring.set_password("TOTP_AES_ENCRYPTION",username,base64.b64encode(key).decode("utf-8"))
    return key


def add_user(username, password,totp_key,got_key=False):
    aes_key=generate_store_aes_key(username)
    password_she256=hashlib.sha256(password.encode()).hexdigest()
    cur.execute(f"""
        INSERT OR REPLACE INTO users 
            (username,password, gotKey,totpKey) VALUES (?,?,?,?)
    """,(username,password_she256,got_key,encrypt_totp(aes_key,totp_key)))
    con.commit()
    con.close()

def encrypt_totp(aes_key, totp_value):
    # Padding the TOTP to match AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(totp_value.encode()) + padder.finalize()

    # AES Encryption
    iv = os.urandom(16)  # Initialization vector for CBC mode


    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_totp = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_totp  # Prepend IV to the ciphertext

def decrypt_totp(aes_key, encrypted_totp):
    iv = encrypted_totp[:16]  # Extract IV from the beginning
    ciphertext = encrypted_totp[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_totp = decryptor.update(ciphertext) + decryptor.finalize()
    print(b"B "+decrypted_padded_totp)
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_totp = unpadder.update(decrypted_padded_totp) + unpadder.finalize()

    return decrypted_totp.decode()

def check_user(username,password,totp):
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    encoded_aes_key=keyring.get_password("TOTP_AES_ENCRYPTION",username)
    aes_key=base64.b64decode(encoded_aes_key)



    try:
        res = cur.execute("SELECT username, password, gotKey, totpKey from users where username=? AND password=? ",(username, hashlib.sha256(password.encode()).hexdigest()))
        user= res.fetchall()
        # print(user)
        # print(decrypt_totp(aes_key,user[0][3]))
        totp_server = pyotp.TOTP(decrypt_totp(aes_key,user[0][3]))
        if totp_server.now() != totp:
            return -1
        con.close()
    except Exception as E:
        raise E


    if user:
        return user[0][2]
    return -1

if __name__=="__main__":
    key=pyotp.random_base32()
    key="C2PJL3YGQVKAIDC5QJF7DYFPFTQ2QBET"
    totp = pyotp.TOTP(key)
    add_user("aviv","12345678",key)
    print(check_user("aviv","12345678",totp.now()))
