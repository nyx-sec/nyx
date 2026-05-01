// DATA_EXFIL allowlist-suppression fixture.
//
// The destination URL has a static prefix (`https://api.internal/...`) that
// the test harness installs as a trusted destination via
// [detectors.data_exfil.trusted_destinations].  The body still carries a
// Sensitive source (`req.cookies.session`), but routing it through a known-
// trusted upstream is a *legitimate* forwarding pipeline: the cap is
// suppressed for this filter only.
//
// Driven by `fetch_data_exfil_suppression_tests.rs`.
function leakBody(req) {
    var payload = req.cookies.session;
    fetch('https://api.internal/forward', {
        method: 'POST',
        body: payload,
    });
}
