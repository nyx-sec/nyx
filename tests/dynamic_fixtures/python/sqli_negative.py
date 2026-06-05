"""SQL injection — negative fixture.

Safe function: uses parameterized queries.
Expected verdict: NotConfirmed (parameterized query prevents injection).
"""
import sqlite3


def login(username):
    """Safe login: parameterized query prevents SQL injection."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    # Safe: parameterized query
    rows = conn.execute("SELECT name FROM users WHERE name=?", (username,)).fetchall()
    for row in rows:
        print(row[0])
    conn.close()
