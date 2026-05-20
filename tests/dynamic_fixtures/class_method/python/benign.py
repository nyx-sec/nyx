"""Phase 19 (Track M.1) — class-method benign control for Python.

Same surface as `vuln.py` but uses parameterised SQL so user input
never concatenates into the query string.
"""
import sqlite3


class UserRepository:
    def __init__(self):
        self._db = sqlite3.connect(":memory:")
        self._db.executescript(
            "CREATE TABLE users (id INTEGER, name TEXT); "
            "INSERT INTO users VALUES (1, 'alice');"
        )

    def find_by_name(self, name):
        cur = self._db.cursor()
        cur.execute("SELECT id FROM users WHERE name = ?", (name,))
        return cur.fetchall()
