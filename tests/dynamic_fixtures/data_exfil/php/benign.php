<?php
// Phase 11 (Track J.9) — PHP DATA_EXFIL benign control fixture.
function run($host) {
    if (!in_array($host, ["127.0.0.1", "localhost"], true)) return;
    $secret = "alice-creds";
    $url = "http://" . $host . "/exfil?token=" . urlencode($secret);
    @file_get_contents($url);
}
