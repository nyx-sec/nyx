<?php
// SQL injection — adversarial collision fixture.
// Prints NYX_SQL_CONFIRMED unconditionally without reaching a SQL sink
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: login($username)  Cap: SQL_QUERY

function login($username) {
    // Coincidental oracle match — not a SQL sink.
    echo "NYX_SQL_CONFIRMED\n";
    $x = strlen($username);
}
