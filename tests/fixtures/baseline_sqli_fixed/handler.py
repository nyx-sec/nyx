import sqlite3

def get_user(db, user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
