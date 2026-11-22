<?php
// Superglobals reaching echo through a null-coalesce or a ternary branch.
function coalesce() {
    echo $_GET['a'] ?? 'none';
}

function ternary_isset() {
    echo isset($_GET['c']) ? $_GET['c'] : '';
}

function short_ternary() {
    echo $_GET['d'] ?: 'none';
}

function ternary_else_branch($flag) {
    echo $flag ? 'x' : $_GET['e'];
}
