<?php
// Phase 15 — Slim/Laravel-style route closure, benign.
// Validates payload before invoking sink.

$GLOBALS['__nyx_route'] = function ($payload) {
    if (!preg_match('/^[A-Za-z0-9]{1,32}$/', (string)$payload)) {
        echo "invalid\n";
        return "invalid";
    }
    $out = shell_exec("echo hello");
    echo $out;
    return $out;
};

if (false) {
    $app->get('/run', $GLOBALS['__nyx_route']);
}
