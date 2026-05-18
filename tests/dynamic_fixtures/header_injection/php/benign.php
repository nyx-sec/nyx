<?php
// Phase 08 (Track J.6) — PHP HEADER_INJECTION benign control fixture.
//
// Same shape as `vuln.php` but URL-encodes the value first via
// `urlencode`, so CRLF bytes land as `%0D%0A` and the wire keeps a
// single header.
function run($value) {
    header("Set-Cookie: " . urlencode($value));
}
