"""SQL injection — unsupported fixture.

This file contains a vulnerable class method. The test creates a Diag
with `confidence = Low`, which makes `from_finding` return
`Err(UnsupportedReason::ConfidenceTooLow)`.

Expected verdict: Unsupported(ConfidenceTooLow)
"""
import sqlite3


class UserRepository:
    """Vulnerable class method — entry kind unsupported in current milestone."""

    def find_user(self, name):
        conn = sqlite3.connect(":memory:")
        query = "SELECT * FROM users WHERE name='" + name + "'"
        return conn.execute(query).fetchall()
