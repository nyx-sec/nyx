<?php
// Phase 15 — top-level script (no function entry), benign.
// Validates payload before invoking sink.

$payload = getenv('NYX_PAYLOAD') ?: '';
if (!preg_match('/^[A-Za-z0-9]{1,32}$/', $payload)) {
    echo "invalid\n";
    exit(0);
}
$out = shell_exec("echo hello");
echo $out;
