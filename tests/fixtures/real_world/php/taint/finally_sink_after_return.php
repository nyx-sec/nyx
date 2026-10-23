<?php
function cleanup() {
    $dir = $_GET['dir'];
    try {
        return 'ok';
    } finally {
        system('rm -rf ' . $dir);
    }
}

function rotate() {
    $dir = $_GET['dir'];
    try {
        return 'ok';
    } finally {
        system('logrotate /etc/app.conf');
    }
}
