<?php
// The try body returns, and the finally clause still runs.
function cleanup() {
    $dir = $_GET['dir'];
    try {
        return 'ok';
    } finally {
        system('rm -rf ' . $dir);
    }
}
