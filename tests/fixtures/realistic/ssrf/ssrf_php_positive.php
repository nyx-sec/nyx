<?php
// Phase 14 fixture (PHP positive) — attacker-controlled URL flows
// directly into `curl_exec`. The `$_GET['url']` source taints the
// curl handle through `curl_setopt(..., CURLOPT_URL, $tainted)`,
// which fires the Phase 14 SSRF gate at the option-bind step.
$ch = curl_init();
$target = $_GET['url'];
curl_setopt($ch, CURLOPT_URL, $target);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$body = curl_exec($ch);
curl_close($ch);
echo $body;
