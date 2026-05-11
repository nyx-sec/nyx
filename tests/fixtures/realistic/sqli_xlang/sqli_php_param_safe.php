<?php
// Phase 15 negative — PHP PDO prepared-statement parameterised.
// `prepare` is a SQL_QUERY sanitizer; the SQL string is a literal
// with `:id` placeholder, and the bind value is a constant so no
// taint reaches the executed query.  Mirrors phase 07's safe
// parameterised shape.

$pdo = new PDO('sqlite:app.db');
$_unused = $_GET['name'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindValue(':id', 1, PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll();
print_r($rows);
