// Unsafe: tainted env value flows into `response.headers_mut().insert`.
// HEADER_INJECTION fires on the value argument.
use std::env;

fn handler(response: &mut http::Response<()>) {
    let lang = env::var("LANG").unwrap_or_default();
    let value = http::HeaderValue::from_str(&lang).unwrap();
    response.headers_mut().insert("X-Lang", value);
}
