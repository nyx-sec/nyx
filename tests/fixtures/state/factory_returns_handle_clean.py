import sqlite3

# Each function hands its handle to the caller.  Expected: no resource
# findings.

def open_log(path):
    f = open(path, "a")
    return f


def get_conn(db):
    conn = sqlite3.connect(db)
    conn.isolation_level = None
    return conn


def direct(path):
    return open(path)


def with_meta(path):
    f = open(path)
    return f, path
