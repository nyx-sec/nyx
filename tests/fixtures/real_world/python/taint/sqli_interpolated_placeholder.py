import sqlite3
from flask import request

TABLE = "users"


def fstring_order_by():
    sort = request.args.get("sort")
    limit = request.args.get("limit")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM users ORDER BY {sort} LIMIT ?", (limit,))
    return str(cur.fetchall())


def concatenated_fstring():
    sort = request.args.get("sort")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users ORDER BY " f"{sort}" " LIMIT ?", (10,))
    return str(cur.fetchall())


def assigned_result():
    sort = request.args.get("sort")
    cur = sqlite3.connect("app.db").cursor()
    rows = cur.execute(f"SELECT * FROM users ORDER BY {sort} LIMIT ?", (5,))
    return str(rows)


def constant_table_bound_value():
    uid = request.args.get("id")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (uid,))
    return str(cur.fetchall())


def constant_query_bound_value():
    uid = request.args.get("id")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return str(cur.fetchall())
