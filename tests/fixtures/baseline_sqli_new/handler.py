import os
import sqlite3

def get_user(db):
    user_id = os.getenv("USER_ID")
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))

def get_post(db):
    post_id = os.getenv("POST_ID")
    query = "SELECT * FROM posts WHERE id = " + post_id
    return db.execute(query)
