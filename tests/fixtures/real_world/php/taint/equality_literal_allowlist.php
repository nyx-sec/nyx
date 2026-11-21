<?php
function list_safe($conn) {
    $dir = $_GET['dir'];
    if ($dir !== 'asc' && $dir !== 'desc') {
        exit;
    }
    mysqli_query($conn, "SELECT * FROM t ORDER BY id " . $dir);
}

function list_loose_numeric($conn) {
    $n = $_GET['n'];
    if ($n == 0) {
        mysqli_query($conn, "SELECT * FROM t LIMIT " . $n);
    }
}
