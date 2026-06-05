// Phase 08 (Track J.6) — JavaScript HEADER_INJECTION benign control
// fixture.
//
// Same shape as `vuln.js` but URL-encodes the value first via
// `encodeURIComponent`, so CRLF bytes land as `%0D%0A` and the wire
// keeps a single header.
const http = require('http');

function run(res, value) {
  res.setHeader('Set-Cookie', encodeURIComponent(value));
}

module.exports = { run };
