<?php
function requested_host() {
    return $_GET['host'];
}

function fixed_host() {
    return 'localhost';
}

function ping() {
    $host = requested_host();
    system("ping -c 1 " . $host);
}

function ping_local() {
    $host = fixed_host();
    system("ping -c 1 " . $host);
}

ping();
ping_local();
