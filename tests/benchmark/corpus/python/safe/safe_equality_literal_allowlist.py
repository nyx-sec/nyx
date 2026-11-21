import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/list")
def list_rows():
    order = request.args.get("order")
    if order != "asc" and order != "desc":
        return "bad", 400
    conn = sqlite3.connect("x.db")
    rows = conn.execute("SELECT * FROM t ORDER BY id " + order).fetchall()
    conn.close()
    return {"n": len(rows)}
