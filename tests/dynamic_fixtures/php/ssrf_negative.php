<?php
// SSRF — negative fixture.
// Safe: only allows http/https scheme; file:// and others rejected.
// Entry: fetchUrl($url)  Cap: SSRF
// Expected verdict: NotConfirmed

function fetchUrl($url) {
    $parsed = parse_url($url);
    $scheme = $parsed['scheme'] ?? '';
    if ($scheme !== 'http' && $scheme !== 'https') {
        echo "Scheme not allowed: " . $scheme . "\n";
        return;
    }
    $content = @file_get_contents($url);
    if ($content !== false) {
        echo substr($content, 0, 64);
    }
}
