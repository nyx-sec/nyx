import sqlite3

from flask import request


def posts_page():
    page = request.args.get("page", 1, type=int)
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM posts LIMIT 20 OFFSET {page * 20}").fetchall()
