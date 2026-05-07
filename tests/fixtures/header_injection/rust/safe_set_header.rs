// Safe: env value routed through the project-local `strip_crlf` helper
// before being written to the response header.
use std::env;

fn strip_crlf(raw: &str) -> String {
    raw.replace('\r', "").replace('\n', "")
}

fn handler(response: &mut http::Response<()>) {
    let lang = env::var("LANG").unwrap_or_default();
    let safe = strip_crlf(&lang);
    let value = http::HeaderValue::from_str(&safe).unwrap();
    response.headers_mut().insert("X-Lang", value);
}
