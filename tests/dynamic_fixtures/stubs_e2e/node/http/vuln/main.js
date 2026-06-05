// Phase 10 (Track D.3) stub-end-to-end fixture: Node + HTTP.
//
// The verifier publishes:
//
//   * NYX_HTTP_ENDPOINT - http://127.0.0.1:{port} the HttpStub listens on.
//   * NYX_HTTP_LOG      - companion log path the harness appends attempted
//                         outbound calls to so the host HttpStub picks them
//                         up on drain_events() even when the request bypasses
//                         the on-the-wire listener (DNS-mocked,
//                         network-isolated sandbox, pre-flight check).
//
// This fixture exercises the side-channel path: it records an attempted
// SSRF call to http://169.254.169.254/latest/meta-data/ through the Node
// shim helper __nyx_stub_http_record without issuing the actual network
// call.  The companion test in tests/stubs_e2e_per_lang.rs splices in
// crate::dynamic::lang::javascript::probe_shim ahead of this source, runs
// it with both env vars set, and asserts the stub captured the attempt.

function main() {
    const method = 'GET';
    const url = 'http://169.254.169.254/latest/meta-data/';
    const body = '';
    // Record the attempted call through the probe shim so the host
    // HttpStub captures it on the next drain_events() call even when the
    // harness never reaches the on-the-wire listener.
    __nyx_stub_http_record(method, url, body, { driver: 'node:http' });
    // Echo so the host can confirm the driver ran end-to-end.
    console.log(process.env.NYX_HTTP_ENDPOINT || 'no-endpoint');
}

main();
