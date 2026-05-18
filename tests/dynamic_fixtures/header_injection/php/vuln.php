<?php
// Phase 08 (Track J.6) — PHP HEADER_INJECTION vuln fixture.
//
// The function concatenates the attacker-controlled `$value` directly
// into a `Set-Cookie` header set via the built-in `header()` function.
// A payload carrying `\r\nSet-Cookie: nyx-injected=pwn` splits the
// single header into two on the wire.
function run($value) {
    header("Set-Cookie: " . $value);
}
