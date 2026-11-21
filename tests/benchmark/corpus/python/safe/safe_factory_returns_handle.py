import sqlite3


def open_log(path):
    f = open(path, "a")
    return f


def get_conn(db):
    conn = sqlite3.connect(db)
    conn.isolation_level = None
    return conn


def direct(path):
    return open(path)
