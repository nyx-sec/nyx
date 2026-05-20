"""Phase 19 (Track M.1) — class-method vuln with constructor deps.

`UserController.__init__` takes an HTTP client + a database connection
(controller → service → repository shape).  The Phase 19 harness's
`_nyx_build_receiver` walks the ctor formals, stubs each with the
matching `Mock*` test double from `src/dynamic/stubs/mocks.rs`, and
invokes the sink method.
"""
import sqlite3


class UserController:
    def __init__(self, http_client, db_connection):
        # Phase 19 harness wires MockHttpClient + MockDatabaseConnection
        # through these two formals so the ctor returns without I/O.
        self._http = http_client
        self._db = db_connection or sqlite3.connect(":memory:")

    def search(self, query):
        cur = self._db.cursor() if hasattr(self._db, "cursor") else None
        if cur is None:
            return None
        # SINK: concatenated SQL
        sql = "SELECT 1 FROM dual WHERE x = '" + query + "'"
        try:
            cur.execute(sql)
        except Exception:
            pass
        return None
