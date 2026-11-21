import sqlite3

# Expected: no resource findings.

def not_conn(db):
    conn = sqlite3.connect(db)
    if not conn:
        return None
    conn.execute("SELECT 1")
    conn.close()
    return 1


def conn_is_none(db):
    conn = sqlite3.connect(db)
    if conn is None:
        return None
    conn.execute("SELECT 1")
    conn.close()
    return 1
