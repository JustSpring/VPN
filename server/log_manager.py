import sqlite3
import sqlite3
from datetime import datetime

def recreate_log_table():
    # Connect to the SQLite database
    con = sqlite3.connect("log.db")
    cur = con.cursor()

    # Delete the table if it exists
    cur.execute("DROP TABLE IF EXISTS log")

    # Create a new `log` table
    cur.execute("""
        CREATE TABLE log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            time TEXT NOT NULL
        )
    """)

    # Commit changes and close the connection
    con.commit()
    con.close()

def add_logging( user, action):
    con = sqlite3.connect("log.db")
    cur = con.cursor()
    cur.execute(f"""
            INSERT INTO log 
                (user, action, time) VALUES (?,?,?)
        """, (user, action, datetime.now().strftime("%d-%m-%Y %H:%M:%S")))
    con.commit()
    con.close()

if __name__=="__main__":
    recreate_log_table()