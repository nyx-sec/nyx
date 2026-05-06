<?php
// Safe: $_GET['lang'] routed through the project-local `strip_crlf` helper
// before concatenation.
function strip_crlf($raw) {
    return str_replace(["\r", "\n"], ["", ""], $raw);
}

$lang = $_GET['lang'];
$safe = strip_crlf($lang);
header("X-Lang: " . $safe);
