<?php
// Phase 15 — CLI script with $argv, benign.
// Validates $argv[1] then runs a fixed echo.

$payload = $argv[1] ?? '';
if (!preg_match('/^[A-Za-z0-9]{1,32}$/', $payload)) {
    echo "invalid\n";
    exit(0);
}
$out = shell_exec("echo hello");
echo $out;
