<?php
function find_user($conn) {
    $id = $_GET['id'];
    $q = "SELECT * FROM users WHERE id = " . intval($id);
    return mysqli_query($conn, $q);
}
