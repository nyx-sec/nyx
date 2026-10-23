<?php
function requested_host() {
    return $_GET['host'];
}

function ping() {
    $host = requested_host();
    system("ping -c 1 " . $host);
}

ping();
