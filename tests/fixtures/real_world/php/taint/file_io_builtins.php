<?php
// Filesystem builtins fed a request-controlled path.
function remove_dump() {
    $dir = '/var/dumps/';
    $ok = !unlink($dir . $_GET['dump']);
    return $ok;
}

function move_dump() {
    rename('/var/dumps/' . $_POST['from'], '/var/archive/x');
}

function make_dir() {
    mkdir('/var/data/' . $_POST['name']);
}

function drop_dir() {
    rmdir('/var/data/' . $_POST['name']);
}

function stamp() {
    touch('/var/data/' . $_POST['name']);
}

function open_mode() {
    chmod('/var/data/' . $_POST['name'], 0777);
}

function send_file() {
    readfile('/var/data/' . $_GET['f']);
}

function lines() {
    return file('/var/data/' . $_GET['f']);
}

function listing() {
    return scandir('/var/data/' . $_GET['d']);
}
