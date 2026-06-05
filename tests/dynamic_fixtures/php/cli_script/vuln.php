<?php
// Phase 15 — CLI script with $argv, vulnerable.
// Top-level body reads $argv[1] and pipes to /bin/sh -c.

echo "__NYX_SINK_HIT__\n";

$payload = $argv[1] ?? '';
$out = shell_exec("echo hello " . $payload);
echo $out;
