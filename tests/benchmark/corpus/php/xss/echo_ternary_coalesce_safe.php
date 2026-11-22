<?php
// A superglobal that only decides the branch, or is escaped or cast, stays quiet.
function condition_only() {
    echo $_GET['a'] ? 'yes' : 'no';
}

function escaped() {
    echo htmlspecialchars($_GET['b'] ?? '');
}

function cast_branch() {
    echo isset($_GET['c']) ? (int) $_GET['c'] : 0;
}

function tainted_test_only() {
    $v = $_GET['v'];
    echo isset($v) ? 'yes' : 'no';
}
