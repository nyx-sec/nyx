<?php
// Phase 15 — PHP PDO raw-string concat SQLi positive.
// `pdo.query` is a flat SQL_QUERY sink in `labels/php.rs`;
// `$_GET['name']` flows directly into the SQL string via
// concatenation with no parameterisation.

$pdo = new PDO('sqlite:app.db');
$name = $_GET['name'];
$rows = $pdo->query("SELECT * FROM users WHERE name = '" . $name . "'");
print_r($rows);
