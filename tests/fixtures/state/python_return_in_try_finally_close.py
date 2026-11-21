import sqlite3


def count(path):
    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        cur.execute("select count(*) from t")
        return cur.fetchone()[0]
    finally:
        conn.close()


def first_line(path, quick):
    f = open(path)
    try:
        if quick:
            return ""
        return f.readline()
    finally:
        f.close()
