<?php
function list_users($mysqli) {
    $allowed = ['name', 'created_at'];
    $requested = $_GET['sort'];
    $sort = in_array($requested, $allowed, true) ? $requested : 'name';
    return $mysqli->query("SELECT * FROM users ORDER BY $sort");
}
