import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)
SORTS = ["name", "date"]


def validate_page(v):
    return v.isdigit()


@app.route("/reread")
def reread():
    value = request.args["page"]
    if not validate_page(value):
        return "bad", 400
    value = request.args["sort"]
    os.system("echo " + value)
    return "ok"


@app.route("/append")
def append():
    value = request.args["page"]
    if not validate_page(value):
        return "bad", 400
    value = value + request.args["suffix"]
    os.system("echo " + value)
    return "ok"


@app.route("/strip")
def strip():
    value = request.args["page"]
    if not validate_page(value):
        return "bad", 400
    value = value.strip()
    os.system("echo " + value)
    return "ok"


@app.route("/items")
def items():
    sort = request.args.get("sort")
    if sort not in SORTS:
        return "bad", 400
    conn = sqlite3.connect("x.db")
    sql = "SELECT * FROM items ORDER BY " + sort + " LIMIT " + request.args.get("limit")
    conn.execute(sql)
    return "ok"
