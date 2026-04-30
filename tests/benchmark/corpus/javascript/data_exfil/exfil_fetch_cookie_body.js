// DATA_EXFIL: a session cookie (Sensitive-tier source) flows into the
// outbound body of fetch() at a fixed destination. SSRF must NOT fire
// because the URL is a hardcoded literal.
function leakBody(req) {
    var payload = req.cookies.session;
    fetch('/endpoint', {
        method: 'POST',
        body: payload,
    });
}
