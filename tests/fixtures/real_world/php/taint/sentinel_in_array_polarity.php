<?php

function safe_strict_false() {
    $cmd = $_GET['cmd'];
    $allowed = ['ls', 'pwd'];
    if (in_array($cmd, $allowed, true) === false) {
        die('bad');
    }
    system($cmd);
}

function safe_yoda_false() {
    $cmd = $_GET['cmd'];
    $allowed = ['ls', 'pwd'];
    if (false === in_array($cmd, $allowed, true)) {
        die('bad');
    }
    system($cmd);
}

function vuln_yoda_false() {
    $cmd = $_GET['cmd'];
    $allowed = ['ls', 'pwd'];
    if (false === in_array($cmd, $allowed, true)) {
        system($cmd);
    }
}
