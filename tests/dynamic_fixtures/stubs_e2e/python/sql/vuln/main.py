"""Phase 10 (Track D.3) stub-end-to-end fixture: Python + SQL.

The verifier publishes:

* ``NYX_SQL_ENDPOINT`` — absolute path of a SQLite DB the SqlStub owns.
* ``NYX_SQL_LOG``      — companion log path the harness appends executed
  queries to so the host SqlStub picks them up on ``drain_events()``.

This fixture exercises both: it opens the stub DB with stdlib ``sqlite3``,
runs a tautology SELECT (``OR 1=1``), and forwards the executed query to
the stub through the Python shim helper ``__nyx_stub_sql_record``.  The
companion test in ``tests/stubs_e2e_per_lang.rs`` splices in
``crate::dynamic::lang::python::probe_shim`` ahead of this source, runs it
with both env vars set, and asserts the stub captured the tautology.
"""

import os
import sqlite3


def main():
    db_path = os.environ.get("NYX_SQL_ENDPOINT")
    if not db_path:
        return
    query = "SELECT 1 WHERE 'a' = 'a' OR 1=1 --"
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(query).fetchall()
        for row in rows:
            print(row[0])
    finally:
        conn.close()
    # Record the executed query through the probe shim so the host
    # SqlStub captures it on the next drain_events() call.
    __nyx_stub_sql_record(query, driver="sqlite3")


if __name__ == "__main__":
    main()
