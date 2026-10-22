import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/a")
def list_a():
    order = request.args.get("order")
    if order != "asc" and order != "desc":
        return "bad", 400
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT * FROM t ORDER BY id " + order)
    return "ok"


@app.route("/b")
def list_b():
    order = request.args.get("order")
    if order == "asc":
        print("ascending")
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT * FROM t ORDER BY id " + order)
    return "ok"
