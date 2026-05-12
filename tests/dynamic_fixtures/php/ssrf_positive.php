<?php
// SSRF — positive fixture.
// Vulnerable: fetches a user-controlled URL via file_get_contents.
// PHP's file_get_contents supports file:// scheme natively.
// Entry: fetchUrl($url)  Cap: SSRF
// Expected verdict: Confirmed (file:///etc/passwd → "daemon:" in output)

function fetchUrl($url) {
    echo "__NYX_SINK_HIT__\n";
    $content = @file_get_contents($url);
    if ($content !== false) {
        echo $content;
    }
}
