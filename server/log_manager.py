import sqlite3
import sqlite3
from datetime import datetime

def add_logging( user, action):
    con = sqlite3.connect("log.db")
    cur = con.cursor()
    cur.execute(f"""
            INSERT INTO log 
                (user, action, time) VALUES (?,?,?)
        """, (user, action, datetime.now().strftime("%d-%m-%Y %H:%M:%S")))
    con.commit()
    con.close()