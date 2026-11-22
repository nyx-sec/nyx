<?php
// FILE_IO builtins called with a leading backslash or consumed by `or die`.
function global_namespace() {
    \unlink($_GET['p']);
}

function assigned_or_die() {
    $f = $_GET['p'];
    $ok = unlink($f) or die('cannot remove');
}

function plain_or_die() {
    unlink($_GET['q']) or die('cannot remove');
}
