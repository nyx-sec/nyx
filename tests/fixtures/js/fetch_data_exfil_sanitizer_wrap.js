// DATA_EXFIL sanitizer-convention fixture.
//
// `logEvent({user: req.cookies.session})` routes a Sensitive cookie source
// through a named telemetry boundary.  The forwarding-wrapper convention
// (see docs/detectors/taint.md) treats `logEvent` as a default
// `Sanitizer(Cap::DATA_EXFIL)` so the cap does NOT fire on this call.
//
// Driven by `fetch_data_exfil_suppression_tests.rs`.
function track(req) {
    logEvent({
        user: req.cookies.session,
    });
}
