<?php
// Phase 15 — top-level script (no function entry), vulnerable.
// Body reads NYX_PAYLOAD env var directly and pipes to /bin/sh -c.

echo "__NYX_SINK_HIT__\n";

$payload = getenv('NYX_PAYLOAD') ?: '';
$out = shell_exec("echo hello " . $payload);
echo $out;
