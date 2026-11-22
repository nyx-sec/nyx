<?php
// Escaped or numeric forms of the same direct reads stay quiet.
function show_escaped() {
    echo htmlspecialchars($_GET['a']);
}

function show_concat_escaped() {
    echo 'Hello ' . htmlspecialchars($_GET['b']);
}

function show_cast() {
    echo (int) $_GET['n'];
}

function show_print_escaped() {
    print htmlspecialchars($_GET['c'], ENT_QUOTES);
}

function show_literal() {
    echo 'static ', 42;
}
