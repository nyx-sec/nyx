# Phase 08 (Track J.6) — Python raw-socket HEADER_INJECTION vuln fixture.
#
# Writes the response status line and headers directly to the wire via
# `self.wfile.write`, bypassing the framework-level CRLF validator that
# werkzeug / Flask / axum / Tomcat would otherwise interpose.  A payload
# carrying `\r\nSet-Cookie: ...` splits the single Set-Cookie header
# into two on the wire, producing the canonical smuggled-second-header
# shape that `ProbeKind::HeaderWireFrame` is designed to catch.
#
# The harness (`src/dynamic/lang/python.rs::emit_header_injection_harness`)
# detects the `BaseHTTPRequestHandler` import in this file and routes
# through the tier-(b) wire-frame branch: boot `HTTPServer` on a
# loopback port, issue one `GET /` over a raw socket, read the bytes
# the handler wrote to the response socket, and emit them as a
# `ProbeKind::HeaderWireFrame` record.
from http.server import BaseHTTPRequestHandler


class VulnHandler(BaseHTTPRequestHandler):
    # Set by the harness before each request.  Bytes go straight onto
    # the wire with no encoding pass.
    cookie_value: bytes = b""

    def do_GET(self):
        body = b"ok\n"
        raw = (
            b"HTTP/1.0 200 OK\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"Set-Cookie: " + self.__class__.cookie_value + b"\r\n"
            b"\r\n"
        ) + body
        self.wfile.write(raw)

    def log_message(self, *args, **kwargs):
        # Silence default stderr logging so the harness captures only
        # the probe + sink-hit sentinel.
        return
