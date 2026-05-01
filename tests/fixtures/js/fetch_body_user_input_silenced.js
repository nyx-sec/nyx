// DATA_EXFIL silenced regression fixture: plain user input echoed into the
// body of an outbound `fetch` to a fixed URL must NOT fire `Cap::DATA_EXFIL`.
// The user already controls `req.body.message` — surfacing it back into the
// request payload is not a cross-boundary disclosure.  This is the canonical
// false-positive class for API gateways and telemetry forwarders that proxy
// `req.body`, killed by the source-sensitivity gate in `ast.rs`.
//
// Driven by `fetch_data_exfil_integration_tests.rs`.
function forward(req) {
    var payload = req.body.message;
    fetch('/endpoint', {
        method: 'POST',
        body: payload,
    });
}
