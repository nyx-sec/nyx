<?php
function limit_rows($conn) {
    $n = $_GET['n'];
    if ($n == 0) {
        mysqli_query($conn, "SELECT * FROM t LIMIT " . $n);
    }
}
