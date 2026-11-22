<?php
// Same shapes with a fixed path or a basename-reduced value.
function global_namespace() {
    \unlink('/tmp/fixed.lock');
}

function assigned_or_die() {
    $f = '/tmp/' . basename($_GET['p']);
    $ok = unlink($f) or die('cannot remove');
}

function plain_or_die() {
    unlink('/tmp/fixed.lock') or die('cannot remove');
}
