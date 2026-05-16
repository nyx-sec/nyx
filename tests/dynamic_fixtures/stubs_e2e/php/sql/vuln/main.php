<?php
// Phase 10 (Track D.3) stub-end-to-end fixture: PHP + SQL.
//
// The verifier publishes:
//
//   NYX_SQL_ENDPOINT  absolute path of a SQLite DB the SqlStub owns.
//   NYX_SQL_LOG       companion log path the harness appends executed
//                     queries to so the host SqlStub picks them up on
//                     drain_events().
//
// This fixture opens the stub DB with stdlib SQLite3, runs a tautology
// SELECT (OR 1=1), and forwards the executed query to the stub through
// the PHP shim helper __nyx_stub_sql_record. The companion test in
// tests/stubs_e2e_per_lang.rs splices in
// crate::dynamic::lang::php::probe_shim ahead of this source, runs it
// with both env vars set, and asserts the stub captured the tautology.

function main(): void {
    $db_path = getenv('NYX_SQL_ENDPOINT');
    if ($db_path === false || $db_path === '') {
        return;
    }
    $query = "SELECT 1 WHERE 'a' = 'a' OR 1=1 --";
    $driver = 'none';
    if (class_exists('SQLite3')) {
        $driver = 'SQLite3';
        $db = new SQLite3($db_path);
        $rows = $db->query($query);
        if ($rows !== false) {
            while ($r = $rows->fetchArray(SQLITE3_NUM)) {
                echo $r[0] . "\n";
            }
        }
        $db->close();
    }
    // Record the executed query through the probe shim so the host
    // SqlStub captures it on the next drain_events() call.
    __nyx_stub_sql_record($query, ['driver' => $driver]);
}

main();
