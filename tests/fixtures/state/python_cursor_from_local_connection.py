import sqlite3

# Cursors opened on a connection this function owns share its lifetime.
# Expected: no resource findings.


def count_users(path):
    with sqlite3.connect(path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        return cur.fetchone()[0]


def names(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM users")
    rows = cur.fetchall()
    conn.close()
    return rows
