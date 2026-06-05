<?php
// Phase 15 — Slim/Laravel-style route closure, vulnerable.
// Reads payload and pipes to /bin/sh -c.
// Entry: route closure  Cap: CODE_EXEC

echo "__NYX_SINK_HIT__\n";

$GLOBALS['__nyx_route'] = function ($payload) {
    $out = shell_exec("echo hello " . $payload);
    echo $out;
    return $out;
};

// Slim-shape marker so PhpShape::detect picks RouteClosure.
if (false) {
    $app->get('/run', $GLOBALS['__nyx_route']);
}
