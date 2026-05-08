<?php
// Phase 14 fixture (PHP search-params positive) — attacker-controlled
// URL concatenated with a query parameter and passed to
// `file_get_contents`. The flat `file_get_contents` SSRF rule fires
// because the URL contains attacker-controlled bytes that determine
// the destination scheme/host.
$target = $_GET['target'];
$query = $_GET['q'];
$body = file_get_contents($target . '?q=' . $query);
echo $body;
