import os
import sqlite3

def get_user(db):
    user_id = os.getenv("USER_ID")
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
