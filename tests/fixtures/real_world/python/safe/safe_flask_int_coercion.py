import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/posts")
def posts_page():
    page = request.args.get("page", 1, type=int)
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT * FROM posts LIMIT 20 OFFSET {page * 20}").fetchall()
    conn.close()
    return {"rows": rows}


@app.route("/posts/by-name")
def posts_by_name():
    name = request.args.get("name", "x", type=str)
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT * FROM posts WHERE name = '{name}'").fetchall()
    conn.close()
    return {"rows": rows}


@app.route("/posts/by-title")
def posts_by_title():
    title = request.args.get("title")
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT * FROM posts WHERE title = '{title}'").fetchall()
    conn.close()
    return {"rows": rows}
