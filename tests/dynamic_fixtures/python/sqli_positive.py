"""SQL injection — positive fixture.

Vulnerable function: directly concatenates user input into SQL.
Expected verdict: Confirmed (SQLI corpus UNION payload causes "NYX_SQL_CONFIRMED"
to appear in output when the fixture prints query results).
"""
import sqlite3


def login(username):
    """Vulnerable login: direct string concatenation in SQL query."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    conn.execute("INSERT INTO users VALUES (2, 'bob')")
    # Vulnerable: user input directly concatenated
    query = "SELECT name FROM users WHERE name='" + username + "'"
    try:
        rows = conn.execute(query).fetchall()
        for row in rows:
            print(row[0])
    except sqlite3.OperationalError as e:
        # Error-based: print query on failure (common in debug mode)
        print(f"DB query: {query}")
        print(f"DB error: {e}", end="")
    finally:
        conn.close()
