import os
from flask import request


def ping_strip_semicolon():
    host = request.args["host"]
    host = host.replace(";", "")
    os.system("ping -c 1 " + host)


def ping_strip_ampersand():
    host = request.args["host"]
    host = host.replace("&", "")
    os.system("ping -c 1 " + host)


def user_by_id(cur):
    uid = request.args["id"]
    uid = uid.replace("'", "")
    cur.execute("SELECT * FROM users WHERE id = " + uid)


def user_by_name_quote_doubling(cur):
    name = request.args["name"]
    name = name.replace("'", "''")
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")


def render_escaped():
    t = request.args["t"]
    t = t.replace("<", "&lt;").replace(">", "&gt;")
    return "<p>" + t + "</p>"
