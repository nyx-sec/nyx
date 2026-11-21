<?php
// Query built with `.=`: the request value is appended to the WHERE clause.
$conn = new mysqli('localhost', 'root', '', 'app');
$sql = "SELECT * FROM users WHERE id = ";
$sql .= $_GET['id'];
$conn->query($sql);
