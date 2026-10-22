import os
import shlex
import sqlite3
from flask import request

conn = sqlite3.connect("app.db")


def sort_column(s):
    if s == "name":
        return "name"
    return "id"


def get_cmd():
    v = request.args["cmd"]
    return v


def quote_first(a, b):
    return shlex.quote(a) + " " + b


def partial():
    path = request.args["path"]
    opts = request.args["opts"]
    os.system("ls " + shlex.quote(path) + " " + opts)


def quoted():
    path = request.args["path"]
    opts = request.args["opts"]
    os.system("ls " + shlex.quote(path) + " " + shlex.quote(opts))


def int_beside_name():
    name = request.args["name"]
    limit = request.args["limit"]
    conn.execute(f"SELECT * FROM t WHERE name = '{name}' LIMIT {int(limit)}")


def int_only():
    limit = request.args["limit"]
    conn.execute(f"SELECT * FROM t LIMIT {int(limit)}")


def helper_summary():
    c = request.args["c"]
    s = quote_first("x", c)
    os.system("ls " + s)


def nested_source():
    os.system(get_cmd())


def nested_allowlist():
    conn.execute("SELECT * FROM t ORDER BY " + sort_column(request.args.get("sort")))
