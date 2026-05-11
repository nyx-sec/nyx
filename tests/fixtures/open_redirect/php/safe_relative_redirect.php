<?php
// Safe: $_GET['next'] routed through `ensure_relative_url` which enforces
// a leading `/` and rejects scheme-prefixed values (relative-only path).
function ensure_relative_url($raw) {
    if (!is_string($raw) || strpos($raw, '/') !== 0 || strpos($raw, '//') === 0) {
        return '/';
    }
    return $raw;
}

$next = $_GET['next'];
$safe = ensure_relative_url($next);
header("Location: " . $safe);
