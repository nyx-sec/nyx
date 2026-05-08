<?php
// Phase 14 fixture (PHP negative) — `"https://api.example.com/" . $path`
// produces a StringFact whose prefix is the literal scheme/host, so
// `is_string_safe_for_ssrf` honours the lock and suppresses the SSRF
// sink at `file_get_contents` even though the path component is
// attacker-controlled.
$path = $_GET['path'];
$url = "https://api.example.com/" . $path;
$body = file_get_contents($url);
echo $body;
