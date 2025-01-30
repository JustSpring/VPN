import sqlite3
import sqlite3
from datetime import datetime
import active_users

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

def add_logging(user, action):
    try:
        con = sqlite3.connect("log.db")

        cur = con.cursor()
        cur.execute(f"""
                INSERT INTO log 
                    (user, action, time) VALUES (?,?,?)
            """, (user, action, datetime.now().strftime("%d-%m-%Y %H:%M:%S")))
        con.commit()
        con.close()
    except:
        print("Error adding logging")

def recreate_full_log_table():
    # Connect to the SQLite database
    con = sqlite3.connect("full_log.db")
    cur = con.cursor()

    # Delete the table if it exists
    cur.execute("DROP TABLE IF EXISTS full_log")

    # Create a new `log` table
    cur.execute("""
        CREATE TABLE full_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            site TEXT NOT NULL,
            port TEXT NOT NULL,
            protocol TEXT NOT NULL,
            time TEXT NOT NULL
        )
    """)

    # Commit changes and close the connection
    con.commit()
    con.close()

def add_full_logging(user, site,port,protocol):
    try:
        if user and site:
            con = sqlite3.connect("full_log.db")

            cur = con.cursor()
            cur.execute(f"""
                    INSERT INTO full_log 
                        (user, site,port,protocol,time) VALUES (?,?,?,?,?)
                """, (user, site,port,protocol, datetime.now().strftime("%d-%m-%Y %H:%M:%S")))
            con.commit()
            con.close()
        else:
            print("user or site is null")
    except Exception as e:
        print("Error adding logging for full log")
        print(e)
if __name__=="__main__":
    recreate_log_table()
    print("Deleted & Created log.db")
    recreate_full_log_table()
    print("Deleted & Created full_log.db")

