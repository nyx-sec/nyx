<?php
function find_user($conn) {
    $id = $_GET['id'];
    $name = $_GET['name'];
    $q = "SELECT * FROM users WHERE id = " . intval($id) . " AND name = '" . $name . "'";
    return mysqli_query($conn, $q);
}
