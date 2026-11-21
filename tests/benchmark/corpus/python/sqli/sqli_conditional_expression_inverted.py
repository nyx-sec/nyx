import sqlite3
from flask import Flask, request

app = Flask(__name__)
SORTABLE = {"name", "created_at"}


@app.route("/users")
def users():
    s = request.args.get("sort")
    sort = s if s not in SORTABLE else "name"
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT * FROM users ORDER BY {sort}").fetchall()
    conn.close()
    return {"n": len(rows)}
