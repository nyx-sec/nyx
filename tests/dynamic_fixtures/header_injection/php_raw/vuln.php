<?php
// Phase 08 (Track J.6) — PHP raw-socket HEADER_INJECTION vuln fixture.
//
// Writes the response status line and headers directly to the wire via
// `fwrite($conn, $raw)` against a `stream_socket_server` server-side
// stream, bypassing the framework-level CRLF validator that PHP's
// built-in `header()` (rejected since PHP 5.1.2) or a Slim / Symfony
// / Laravel response serializer would otherwise interpose.  A payload
// carrying `\r\nSet-Cookie: ...` splits the single Set-Cookie header
// into two on the wire, producing the canonical smuggled-second-header
// shape that `ProbeKind::HeaderWireFrame` is designed to catch.
//
// The harness (`src/dynamic/lang/php.rs::emit_header_injection_harness`)
// detects the `stream_socket_server` token in this file and routes
// through the tier-(b) wire-frame branch: bind a loopback server via
// `create_server`, accept one client (`run_once`), issue one raw
// `GET / HTTP/1.0` from the harness, read the bytes the fixture wrote
// to the response stream up to the CRLF-CRLF boundary, and emit them
// as a `ProbeKind::HeaderWireFrame` record.
//
// Uses `stream_socket_server` rather than `socket_create` so the
// fixture has no hard dep on `ext-sockets` (which is core but not
// always built into minimal PHP images); `stream_socket_server`
// resolves through the always-available filesystem-and-network
// stream layer.

// Bytes go straight onto the wire with no encoding pass.  The harness
// installs the cookie value before booting the accept loop, mirroring
// the Ruby `set_cookie_value` and Python `Handler.cookie_value` setters.
$GLOBALS['nyx_cookie_value'] = '';

function set_cookie_value($value) {
    $GLOBALS['nyx_cookie_value'] = (string) $value;
}

function create_server() {
    $errno = 0;
    $errstr = '';
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($server === false) {
        throw new \RuntimeException("stream_socket_server failed: $errno $errstr");
    }
    return $server;
}

function run_once($server) {
    $conn = @stream_socket_accept($server, 5.0);
    if ($conn === false) {
        return;
    }
    try {
        // Drain whatever request bytes the client sent so the kernel
        // does not stall the write that follows.  Ignore errors.
        @stream_set_timeout($conn, 1, 0);
        @fread($conn, 4096);
        $body = "ok\n";
        $cookie = isset($GLOBALS['nyx_cookie_value']) ? $GLOBALS['nyx_cookie_value'] : '';
        $raw = "HTTP/1.0 200 OK\r\n"
             . "Content-Length: " . strlen($body) . "\r\n"
             . "Set-Cookie: " . $cookie . "\r\n"
             . "\r\n"
             . $body;
        @fwrite($conn, $raw);
        @fflush($conn);
    } finally {
        @fclose($conn);
    }
}
