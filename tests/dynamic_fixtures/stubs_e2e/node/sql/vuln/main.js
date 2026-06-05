// Phase 10 (Track D.3) stub-end-to-end fixture: Node + SQL.
//
// The verifier publishes:
//
//   * NYX_SQL_ENDPOINT — absolute path of a SQLite DB the SqlStub owns.
//   * NYX_SQL_LOG      — companion log path the harness appends executed
//     queries to so the host SqlStub picks them up on drain_events().
//
// This fixture mirrors the Python sibling at
// tests/dynamic_fixtures/stubs_e2e/python/sql/vuln/main.py.  It opens
// the stub DB through Node's experimental stdlib `node:sqlite` module
// (Node 22.5+), runs a tautology SELECT (OR 1=1), and forwards the
// executed query to the stub through the JS shim helper
// `__nyx_stub_sql_record`.  When `node:sqlite` is missing (older Node
// or stripped runtimes) the DB exec step is skipped but the shim
// recorder still fires so the stub captures the query regardless.

'use strict';

function main() {
    const dbPath = process.env.NYX_SQL_ENDPOINT;
    if (!dbPath) return;
    const query = "SELECT 1 WHERE 'a' = 'a' OR 1=1 --";

    let driverName = 'none';
    try {
        const sqlite = require('node:sqlite');
        const db = new sqlite.DatabaseSync(dbPath);
        try {
            const rows = db.prepare(query).all();
            for (const row of rows) {
                process.stdout.write(String(Object.values(row)[0]) + '\n');
            }
            driverName = 'node:sqlite';
        } finally {
            db.close();
        }
    } catch (e) {
        // node:sqlite unavailable on this Node version; skip the
        // exec but still record the query so the stub sees the call.
    }

    __nyx_stub_sql_record(query, { driver: driverName });
}

main();
