// Phase 08 (Track J.6) — JavaScript raw-socket HEADER_INJECTION vuln fixture.
//
// Writes the response status line and headers directly to the wire via
// `socket.write`, bypassing the framework-level CRLF validator that
// Node's `http.ServerResponse#setHeader` / Express / axum / Tomcat
// would otherwise interpose.  A payload carrying `\r\nSet-Cookie: ...`
// splits the single Set-Cookie header into two on the wire, producing
// the canonical smuggled-second-header shape that
// `ProbeKind::HeaderWireFrame` is designed to catch.
//
// The harness (`src/dynamic/lang/js_shared.rs::emit_header_injection_harness`)
// detects the `net.createServer` import in this file and routes
// through the tier-(b) wire-frame branch: boot a `net.Server` on a
// loopback port, issue one `GET /` over a raw socket, read the bytes
// the handler wrote to the response socket, and emit them as a
// `ProbeKind::HeaderWireFrame` record.
const net = require('net');

// Set by the harness before each request.  Bytes go straight onto
// the wire with no encoding pass.
let cookieValue = Buffer.alloc(0);

function setCookieValue(value) {
  if (Buffer.isBuffer(value)) {
    cookieValue = value;
  } else {
    cookieValue = Buffer.from(String(value), 'utf8');
  }
}

function createServer() {
  return net.createServer((socket) => {
    socket.once('data', () => {
      const body = Buffer.from('ok\n');
      const head = Buffer.concat([
        Buffer.from('HTTP/1.0 200 OK\r\n'),
        Buffer.from('Content-Length: ' + body.length + '\r\n'),
        Buffer.from('Set-Cookie: '),
        cookieValue,
        Buffer.from('\r\n'),
        Buffer.from('\r\n'),
      ]);
      socket.write(Buffer.concat([head, body]));
      socket.end();
    });
    socket.on('error', () => {});
  });
}

module.exports = { setCookieValue, createServer };
