// Phase 10 (Track D.3) — Rust SQL recorder body-only fragment.
//
// Wrapped at test time by `wrap_rust_fragment(body, shim)` in
// `tests/stubs_e2e_per_lang.rs`: the wrapper prepends the Rust probe
// shim (which carries `__nyx_stub_sql_record`) and a one-line
// `Cargo.toml` so `cargo run --quiet` builds the program in place.
//
// Rust has no stdlib SQLite client (rusqlite is a heavyweight C-link
// dep that would force a libsqlite3-dev prereq on the dynamic CI
// matrix).  The fixture surfaces the attempted tautology query
// through the shim recorder so the host-side SqlStub captures it as
// `driver = "manual"`, mirroring the Phase 26 "no live driver
// available" path that real Rust sink callsites take when the build
// matrix lacks a DB driver.
let _endpoint = std::env::var("NYX_SQL_ENDPOINT").unwrap_or_default();
let query = "SELECT 1 WHERE 'a' = 'a' OR 1=1 --";
let detail: &[(&str, &str)] = &[("driver", "manual")];
__nyx_stub_sql_record(query, detail);
