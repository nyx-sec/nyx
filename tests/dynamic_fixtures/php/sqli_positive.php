<?php
// SQL injection — positive fixture.
// Vulnerable: directly concatenates user input into SQL query string.
// Entry: login($username)  Cap: SQL_QUERY
// Expected verdict: Confirmed (UNION payload echoes NYX_SQL_CONFIRMED)

function login($username) {
    $query = "SELECT name FROM users WHERE name='" . $username . "'";
    echo "__NYX_SINK_HIT__\n";
    // Error-based echo: output the query so UNION payload is visible.
    echo "DB query: " . $query . "\n";
}
