<?php
// Phase 10 (Track D.3) stub-end-to-end fixture: PHP + HTTP.
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
// SSRF call to http://169.254.169.254/latest/meta-data/ through the PHP
// shim helper __nyx_stub_http_record without issuing the actual network
// call.  The companion test in tests/stubs_e2e_per_lang.rs strips this
// leading <?php tag, splices in crate::dynamic::lang::php::probe_shim
// ahead of the remaining body inside a fresh <?php block, runs it with
// both env vars set, and asserts the stub captured the attempt.

function nyx_e2e_main(): void {
    $method = 'GET';
    $url = 'http://169.254.169.254/latest/meta-data/';
    $body = '';
    // Record the attempted call through the probe shim so the host
    // HttpStub captures it on the next drain_events() call even when the
    // harness never reaches the on-the-wire listener.
    __nyx_stub_http_record($method, $url, $body, ['driver' => 'curl']);
    // Echo so the host can confirm the driver ran end-to-end.
    $endpoint = getenv('NYX_HTTP_ENDPOINT');
    echo ($endpoint === false || $endpoint === '') ? 'no-endpoint' : $endpoint;
    echo "\n";
}

nyx_e2e_main();
