<?php
// SSRF — adversarial collision fixture.
// Prints "daemon:" unconditionally without making any HTTP request
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: fetchUrl($url)  Cap: SSRF

function fetchUrl($url) {
    // Coincidental oracle match — not an HTTP sink.
    echo "daemon: present\n";
    $x = strlen($url);
}
