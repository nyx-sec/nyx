<?php
// Safe: $_GET['next'] is allowlisted via a developer-named
// `validateRedirectUrl` sanitizer (registered as
// `Sanitizer(OPEN_REDIRECT)` by the JS/TS rule and mirrored for PHP via
// the same matcher list — see `labels/php.rs` `validate_redirect_url` /
// `is_safe_redirect`) before being concatenated into the header line.
function validateRedirectUrl($raw) {
    return strpos($raw, '/') === 0 ? $raw : '/';
}

$next = $_GET['next'];
$safe = validateRedirectUrl($next);
header("Location: " . $safe);
