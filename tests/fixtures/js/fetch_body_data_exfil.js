// DATA_EXFIL fixture: a fixed destination URL and a sensitive (cookie /
// session) source flowing into the outbound body.  SSRF must NOT fire
// (destination is hardcoded) but `Cap::DATA_EXFIL` must fire because the
// source is Sensitive (`req.cookies.session` carries auth material) — exactly
// the cross-boundary leak the cap targets.
//
// Plain user input echoed back into a body is intentionally not classified
// as data exfiltration, see `fetch_body_user_input_silenced.js`.
//
// Driven by `fetch_data_exfil_integration_tests.rs`.
function leakBody(req) {
    var payload = req.cookies.session;
    fetch('/endpoint', {
        method: 'POST',
        body: payload,
    });
}
