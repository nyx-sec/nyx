// Phase 08 (Track J.6) — JavaScript HEADER_INJECTION vuln fixture.
//
// The function assigns the attacker-controlled `value` directly into a
// Node response's `Set-Cookie` header via `http.ServerResponse
// #setHeader`.  A payload carrying `\r\nSet-Cookie: nyx-injected=pwn`
// splits the single header into two on the wire.
const http = require('http');

function run(res, value) {
  res.setHeader('Set-Cookie', value);
}

module.exports = { run };
