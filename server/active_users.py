import sqlite3
import logging

logging.basicConfig(level=logging.INFO)

# Initialize the database
def initialize_database():
    """
    Create the 'active' table if it does not exist.
    """
    with sqlite3.connect("active_users.db") as con:
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS active (
                username TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                proxy TEXT
            )
        """)
        con.commit()
        logging.info("Database initialized.")
def delete_table():
    with sqlite3.connect("active_users.db") as con:
        cur = con.cursor()
        cur.execute("""
            DROP TABLE active
        """)
        con.commit()
def add_user(username, ip, proxy=None):
    """
    Add or replace a user in the 'active' table.
    """
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO active (username, ip, proxy)
                VALUES (?, ?, ?)
            """, (username, ip, proxy))
            con.commit()
            logging.info(f"User {username} added/updated with IP {ip} and proxy {proxy}.")
    except sqlite3.OperationalError as e:
        logging.error(f"Error adding/updating user {username}: {e}")

def update_proxy(username, proxy):
    """
    Update the proxy for a specific user.
    """
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                UPDATE active
                SET proxy = ?
                WHERE username = ?
            """, (proxy, username))
            con.commit()
            logging.info(f"Proxy for user {username} updated to {proxy}.")
    except sqlite3.OperationalError as e:
        logging.error(f"Error updating proxy for {username}: {e}")

def get_proxy(username):
    """
    Retrieve the proxy for a specific user.
    """
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                SELECT proxy
                FROM active
                WHERE username = ?
            """, (username,))
            result = cur.fetchone()
            if result:
                logging.info(f"Proxy for user {username} retrieved: {result[0]}")
                return result[0]
            else:
                logging.info(f"No proxy found for user {username}.")
                return None
    except sqlite3.OperationalError as e:
        logging.error(f"Error retrieving proxy for {username}: {e}")
        return None

def delete_user(username):
    """
    Delete a user from the 'active' table.
    """
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                DELETE FROM active
                WHERE username = ?
            """, (username,))
            con.commit()
            logging.info(f"User {username} deleted from active users.")
    except sqlite3.OperationalError as e:
        logging.error(f"Error deleting user {username}: {e}")

def get_proxy_by_ip(ip):
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                SELECT proxy
                FROM active
                WHERE ip = ?
            """, (ip,))
            result = cur.fetchone()
            if result:
                logging.info(f"Proxy for IP {ip} retrieved: {result[0]}")
                return result[0]
            else:
                logging.info(f"No proxy found for IP {ip}.")
                return None
    except sqlite3.OperationalError as e:
        logging.error(f"Error retrieving proxy for IP {ip}: {e}")
        return None

if __name__=="__main__":
    delete_table()
    initialize_database()