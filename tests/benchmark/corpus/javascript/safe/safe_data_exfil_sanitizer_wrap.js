// DATA_EXFIL safe: routing a Sensitive cookie source through the named
// telemetry boundary `logEvent` is the developer's explicit decision to
// forward; the default Sanitizer(data_exfil) convention strips the cap.
function track(req) {
    logEvent({
        user: req.cookies.session,
    });
}
