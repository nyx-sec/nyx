<?php
// SQL injection — negative fixture.
// Safe: uses PDO prepared statement; payload is a bound param, not concatenated.
// Entry: login($username)  Cap: SQL_QUERY
// Expected verdict: NotConfirmed

function login($username) {
    $template = "SELECT name FROM users WHERE name = ?";
    // Simulate parameterized execution: template is fixed.
    echo "Executing: " . $template . " param-len=" . strlen($username) . "\n";
}
