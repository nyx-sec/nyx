from flask import request

BY_ID = "SELECT id, name FROM users WHERE id = %(id)s"


def by_id(cur):
    uid = request.args.get("id")
    cur.execute(BY_ID, {"id": uid})
    return cur.fetchall()


def by_name(conn):
    name = request.args.get("name")
    sql = "SELECT id FROM users WHERE name = ?"
    return conn.execute(sql, (name,)).fetchall()
