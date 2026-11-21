import sqlite3

from flask import request

TABLE = "users"
BASE_Q = "SELECT * FROM users"
BY_ID = """
    SELECT id, name
    FROM users
    WHERE id = %(id)s
"""


def by_id(cur):
    uid = request.args.get("id")
    cur.execute(BY_ID, {"id": uid})
    return cur.fetchall()


def base_query_with_bind(cur):
    uid = request.args.get("id")
    cur.execute(BASE_Q + " WHERE id = ?", (uid,))
    return cur.fetchall()


def f_string_over_constant(cur):
    uid = request.args.get("id")
    cur.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (uid,))
    return cur.fetchall()


def literal_concat(cur):
    cur.execute("SELECT a " + "FROM b")
    return cur.fetchall()


def chained_fetch_with_bind():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall()
    conn.close()
    return rows


def sql_in_local_variable():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    sql = "SELECT name FROM users WHERE id = ?"
    rows = conn.execute(sql, (uid,)).fetchall()
    conn.close()
    return rows


def concatenated_query(cur):
    uid = request.args.get("id")
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    return cur.fetchall()


def chained_fetch_concatenated():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT * FROM users WHERE id = " + uid).fetchall()
    conn.close()
    return rows
