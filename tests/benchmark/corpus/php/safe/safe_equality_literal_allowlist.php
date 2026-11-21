<?php
function list_rows($conn) {
    $dir = $_GET['dir'];
    if ($dir !== 'asc' && $dir !== 'desc') {
        exit;
    }
    mysqli_query($conn, "SELECT * FROM t ORDER BY id " . $dir);
}
