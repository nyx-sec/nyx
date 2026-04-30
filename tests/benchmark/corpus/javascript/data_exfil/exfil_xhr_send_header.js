// DATA_EXFIL: a request header (Sensitive-tier source) flows into the
// body of XMLHttpRequest.send(). The destination is a static literal, so
// SSRF must not fire.
function leakHeader(req) {
    var auth = req.headers.authorization;
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/upstream');
    xhr.send(auth);
}
