import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def users():
    sort = request.args.get("sort")
    limit = request.args.get("limit")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM users ORDER BY {sort} LIMIT ?", (limit,))
    return str(cur.fetchall())
