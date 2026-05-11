<?php
// Unsafe: $_GET['lang'] concatenated into a `header()` line.  The bare
// `header` matcher (exact-match sigil) fires on the call.  Tainted input
// without `\r\n` stripping permits response splitting.
$lang = $_GET['lang'];
header("X-Lang: " . $lang);
