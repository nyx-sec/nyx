"""SQL injection fixture with a secrets file in the project.

Used for the secret-bearing fixture test: verifies that the AWS key
from .env does not appear in cache, telemetry, or repro outcome.json
after redaction.

Expected verdict: result depends on execution; secret must never appear
in any output artifact.
"""
import sqlite3
import os


def login(username):
    """Vulnerable login — same as sqli_positive but in a project with .env."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    query = "SELECT name FROM users WHERE name='" + username + "'"
    try:
        rows = conn.execute(query).fetchall()
        for row in rows:
            print(row[0])
    except sqlite3.OperationalError as e:
        print(f"DB query: {query}")
        print(f"DB error: {e}", end="")
    finally:
        conn.close()
