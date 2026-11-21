import sqlite3

# The connection itself is never closed: that is the leak to report.
# Expected: state-resource-leak on the connection.


def first_name(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM users")
    return cur.fetchone()
