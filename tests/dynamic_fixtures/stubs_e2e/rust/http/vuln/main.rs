// Phase 10 (Track D.3) — Rust HTTP recorder body-only fragment.
//
// Wrapped at test time by `wrap_rust_fragment(body, shim)` in
// `tests/stubs_e2e_per_lang.rs`: the wrapper prepends the Rust probe
// shim (which carries `__nyx_stub_http_record`) and a one-line
// `Cargo.toml` so `cargo run --quiet` builds the program in place.
//
// The fragment never issues the actual network call.  It records the
// SSRF attempt at 169.254.169.254/latest/meta-data/ through the shim
// recorder so the host-side HttpStub captures the boundary event.
let _endpoint = std::env::var("NYX_HTTP_ENDPOINT").unwrap_or_default();
let detail: &[(&str, &str)] = &[("driver", "manual")];
__nyx_stub_http_record(
    "GET",
    "http://169.254.169.254/latest/meta-data/",
    None,
    detail,
);
