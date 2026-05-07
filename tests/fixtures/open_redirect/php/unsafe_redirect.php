<?php
// Unsafe: $_GET['next'] flows directly into a `header("Location: ...")`
// line.  The PHP gated SinkGate for `header` activates on the
// `Location:` first-arg prefix and emits OPEN_REDIRECT in addition to
// the existing flat HEADER_INJECTION sink.
$next = $_GET['next'];
header("Location: " . $next);
