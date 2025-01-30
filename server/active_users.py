import sqlite3
import logging

logging.basicConfig(level=logging.INFO)


def initialize_database():

    with sqlite3.connect("active_users.db") as con:
        cur = con.cursor()
        # Create the 'active' table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS active (
                username TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                cert TEXT NOT NULL,
                proxy TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL
            )
        """)

        con.commit()
        logging.info("Database initialized (tables 'active' and 'ports').")


def delete_table():

    with sqlite3.connect("active_users.db") as con:
        cur = con.cursor()
        cur.execute("""
            DROP TABLE IF EXISTS active
        """)
        # If you also want to drop 'ports', uncomment:
        # cur.execute("""DROP TABLE ports""")
        con.commit()


def add_user(username, ip, cert,proxy=None):

    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO active (username, ip,cert, proxy)
                VALUES (?, ?,?, ?)
            """, (username, ip,cert, proxy))
            con.commit()
            logging.info(f"User {username} added/updated with IP {ip} and cert {cert} and proxy {proxy}.")
    except sqlite3.OperationalError as e:
        logging.error(f"Error adding/updating user {username}: {e}")


def update_proxy(username, proxy):

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


def get_name_by_ip(ip):
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                SELECT username
                FROM active
                WHERE ip = ?
            """, (ip,))
            result = cur.fetchone()
            if result:
                return result[0]
            else:
                logging.info(f"No username found for IP {ip}.")
                return None
    except sqlite3.OperationalError as e:
        logging.error(f"Error retrieving proxy for IP {ip}: {e}")
        return None


def get_proxy_by_cert(cert):

    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                SELECT proxy
                FROM active
                WHERE cert = ?
            """, (cert,))
            result = cur.fetchone()
            if result:
                logging.info(f"Proxy for cert {cert} retrieved: {result[0]}")
                return result[0]
            else:
                logging.info(f"No proxy found for cert {cert}.")
                return None
    except sqlite3.OperationalError as e:
        logging.error(f"Error retrieving proxy for cert {cert}: {e}")
        return None


def get_name_by_cert(cert):
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                SELECT username
                FROM active
                WHERE cert = ?
            """, (cert,))
            result = cur.fetchone()
            if result:
                return result[0]
            else:
                logging.info(f"No username found for cert {cert}.")
                return None
    except sqlite3.OperationalError as e:
        logging.error(f"Error retrieving proxy for cert {cert}: {e}")
        return None

# ---------------------------
#  Ports table-specific code
# ---------------------------

def add_port_entry(port, ip, username):
    try:
        if port and ip and username:
            with sqlite3.connect("active_users.db") as con:
                cur = con.cursor()
                cur.execute("""
                    INSERT INTO ports (port, ip, username)
                    VALUES (?, ?, ?)
                """, (port, ip, username))
                con.commit()
                logging.info(f"Port entry added: port={port}, ip={ip}, username={username}")
        else:
            logging.error("PORT OR IP OR USERNAME NULL")
    except sqlite3.OperationalError as e:
        logging.error(f"Error adding port entry for {username}: {e}")


def get_name_by_port(port):
    try:
        with sqlite3.connect("active_users.db") as con:
            cur = con.cursor()
            cur.execute("""
                SELECT username
                FROM ports
                WHERE port = ?
            """, (port,))
            result = cur.fetchone()
            if result:
                return result[0]
            else:
                logging.info(f"No user found for port {port}.")
                return None
    except sqlite3.OperationalError as e:
        logging.error(f"Error retrieving user by port {port}: {e}")
        return None

if __name__ == "__main__":
    # Example usage:
    delete_table()  # If you want to drop the old 'active' table
    initialize_database()

    # add_user("alice", "1.2.3.4", "proxyA")
    # add_port_entry("8080", "1.2.3.4", "alice")
    #
    # # Retrieve all ports
    # ports = get_all_ports()
    # logging.info(f"Ports table contents: {ports}")
