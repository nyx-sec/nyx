"""Phase 19 (Track M.1) — class-method vuln fixture for Python.

`UserRepository.find_by_name` accepts user input and builds a raw SQL
query, classic concatenation-driven SQL injection.  The class has a
zero-arg constructor so the harness builds the receiver without
needing a stubbed dependency.
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
        # SINK: user input concatenated into the query
        sql = "SELECT id FROM users WHERE name = '" + name + "'"
        cur.execute(sql)
        return cur.fetchall()
