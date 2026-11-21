import sqlite3
from contextlib import closing

from flask import request


def posts_page():
    page = request.args.get("page", 1, type=int)
    with closing(sqlite3.connect("app.db")) as conn:
        return conn.execute(f"SELECT * FROM posts LIMIT 20 OFFSET {page * 20}").fetchall()
