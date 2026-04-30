// Regression: a tainted URL flowing through a reqwest chain *without*
// a body-binding step must fire SSRF (taint-unsanitised-flow) but must
// NOT fire DATA_EXFIL.  The chain text reduces to `Client::new.post`
// with no `body|json|form|multipart` segment, so the body-bind chain
// matcher cannot attach.  Guards against the new chain-aware DATA_EXFIL
// rule over-firing on pure URL flows.
fn fetch_url_only() {
    let url = std::env::var("TARGET_URL").unwrap();
    let _ = reqwest::Client::new().post(&url).send();
}
