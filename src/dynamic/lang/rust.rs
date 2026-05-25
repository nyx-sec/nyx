//! Rust harness emitter.
//!
//! Generates a binary crate that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Calls the entry function from `src/entry.rs` with the payload routed
//!    to the correct parameter slot.
//! 3. The entry function calls `println!("__NYX_SINK_HIT__")` before the
//!    actual sink invocation (sink-reachability probe).
//! 4. Captures outcome via stdout markers and exit code (§4.1).
//!
//! Build step: the runner calls `build_sandbox::prepare_rust()` which runs
//! `cargo build --release` in the workdir. `harness.command` is updated to
//! the compiled binary path before sandbox execution.
//!
//! Payload slot support:
//! - `PayloadSlot::Param(0)` — pass payload as `&str` first argument.
//! - `PayloadSlot::EnvVar(name)` — set env var before calling entry.
//! - All other slots (`Stdin`, `Param(n>0)`, `QueryParam`, `HttpBody`, `Argv`)
//!   produce `UnsupportedReason::PayloadSlotUnsupported`. Stdin piping into the
//!   generated harness is not yet wired (deferred).
//!
//! HTML_ESCAPE is n/a for Rust (§15.4).

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use crate::labels::Cap;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for Rust.  Method bodies delegate to the
/// existing free functions in this module.
pub struct RustEmitter;

/// Entry kinds the Rust emitter understands after Phase 16.
///
/// `HttpRoute` covers `actix_web` and `axum` handlers.  `CliSubcommand`
/// covers clap-driven CLIs.  `LibraryApi` covers libfuzzer
/// `fuzz_target!` entry points.  `Function` covers plain free functions
/// and is the fallback when shape detection is inconclusive.
const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::HttpRoute,
    EntryKindTag::CliSubcommand,
    EntryKindTag::LibraryApi,
    EntryKindTag::ClassMethod,
    EntryKindTag::GraphQLResolver,
];

impl LangEmitter for RustEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "rust emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 16 / 19 / 20 / 21 shape dispatch (actix / axum / clap / libfuzzer + future class / msg / job adapters)"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_rust(env)
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        chain_step(prev_output, terminal)
    }
}

/// Phase 26 — Rust chain-step harness.
///
/// Splices the Rust probe shim ([`probe_shim`]) in front of a minimal
/// driver that reads `NYX_PREV_OUTPUT` and writes it on stdout.  The
/// shim references `libc::*` from its `__nyx_install_crash_guard`
/// definition, so a single-file `rustc step.rs` build cannot resolve
/// the symbols.  Instead the step ships a companion `Cargo.toml`
/// pinning `libc = "0.2"` via [`ChainStepHarness::extra_files`] and
/// drives the build through `cargo run --quiet`.
///
/// When `terminal` is set, the driver also calls
/// `__nyx_probe(callee, &[&prev])` and prints
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] so the runner flips
/// `sink_hit` on the chain's last step.
fn chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let shim = probe_shim();
    let mut driver = String::from(
        "use std::env;\nuse std::io::{self, Write};\n\nfn main() {\n    let prev = env::var(\"NYX_PREV_OUTPUT\").unwrap_or_default();\n    let _ = io::stdout().write_all(prev.as_bytes());\n",
    );
    if let Some(t) = terminal {
        let callee = rust_string_literal(&t.sink_callee);
        let sentinel = rust_string_literal(ChainStepHarness::SINK_HIT_SENTINEL);
        driver.push_str(&format!(
            "    __nyx_probe({callee}, &[prev.as_str()]);\n    println!({sentinel});\n",
        ));
    }
    driver.push_str("}\n");
    let source = format!("{shim}\n{driver}");
    let cargo_toml = "[package]\n\
                      name = \"nyx-chain-step\"\n\
                      version = \"0.0.1\"\n\
                      edition = \"2021\"\n\n\
                      [[bin]]\n\
                      name = \"step\"\n\
                      path = \"step.rs\"\n\n\
                      [dependencies]\n\
                      libc = \"0.2\"\n"
        .to_owned();
    ChainStepHarness {
        source,
        filename: "step.rs".to_owned(),
        command: vec!["cargo".to_owned(), "run".to_owned(), "--quiet".to_owned()],
        extra_env: prev_output
            .map(|bytes| {
                vec![(
                    ChainStepHarness::PREV_OUTPUT_ENV.to_owned(),
                    String::from_utf8_lossy(bytes).into_owned(),
                )]
            })
            .unwrap_or_default(),
        extra_files: vec![("Cargo.toml".to_owned(), cargo_toml)],
    }
}

/// Escape a string for safe Rust double-quoted literal embedding.
fn rust_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Phase 09 — Track D.2: synthesise a `Cargo.toml` that pins every
/// captured crate dep.  The base cap-driven dep set lives in
/// [`generate_cargo_toml`]; this function layers the user's direct
/// crate imports on top so the harness build can resolve symbols from
/// crates the entry actually uses.
pub fn materialize_rust(env: &Environment) -> RuntimeArtifacts {
    let mut artifacts = RuntimeArtifacts::new();
    let mut deps: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for d in &env.direct_deps {
        if is_rust_stdlib(d) {
            continue;
        }
        if seen.insert(d.clone()) {
            deps.push(d.clone());
        }
    }
    deps.sort_unstable();

    let mut body = String::with_capacity(256);
    body.push_str("[package]\n");
    body.push_str("name = \"nyx-harness\"\n");
    body.push_str("version = \"0.1.0\"\n");
    body.push_str("edition = \"2021\"\n\n");
    body.push_str("[[bin]]\n");
    body.push_str("name = \"nyx_harness\"\n");
    body.push_str("path = \"src/main.rs\"\n\n");
    body.push_str("[dependencies]\n");
    for d in &deps {
        body.push_str(d);
        body.push_str(" = \"*\"\n");
    }
    artifacts.push("Cargo.toml", body);
    artifacts
}

fn is_rust_stdlib(name: &str) -> bool {
    matches!(
        name,
        "std" | "core" | "alloc" | "proc_macro" | "test" | "self" | "super" | "crate"
    )
}

/// Source of the `__nyx_probe` shim for the Rust harness (Phase 06 —
/// Track C.1).
///
/// Defined here so future sink-rewrite passes can splice
/// `__nyx_probe("os.system", payload)` into the entry source without
/// depending on serde at the harness boundary.  Hand-rolled JSON keeps
/// the shim's only dep on `std`; matches the
/// [`crate::dynamic::probe::SinkProbe`] wire format.
pub fn probe_shim() -> &'static str {
    // Raw-string delimiter is `r##"..."##` (not `r#"..."#`) so the
    // body can contain literal `"# ...` byte sequences without
    // terminating the raw string early.  The Phase 10 stub recorder
    // helpers below emit hash-prefixed log lines (`"# method: ..."`)
    // that would otherwise close `r#"..."#` at the first `"#`.  Same
    // workaround as Java's shim raw string (session 0018) — defensive
    // so future shim extensions that introduce `"#` substrings drop
    // in without further bumps.
    r##"
// ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ──────
#[allow(dead_code)]
const __NYX_DENY_SUBSTRINGS: &[&str] = &[
    "TOKEN","SECRET","PASSWORD","PASSWD","API_KEY","APIKEY","PRIVATE_KEY",
    "CREDENTIAL","SESSION","COOKIE","AUTH","BEARER","AWS_ACCESS","AWS_SESSION",
    "GH_TOKEN","GITHUB_TOKEN","NPM_TOKEN","PYPI_TOKEN","DOCKER_PASS",
];
#[allow(dead_code)]
const __NYX_PAYLOAD_LIMIT: usize = 16 * 1024;
#[allow(dead_code)]
const __NYX_REDACTED: &str = "<redacted-by-nyx-policy>";

#[allow(dead_code)]
fn __nyx_esc(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

#[allow(dead_code)]
fn __nyx_witness_json(sink_callee: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("{\"env_snapshot\":{");
    let mut first = true;
    let mut keys: Vec<(String, String)> = std::env::vars().collect();
    keys.sort();
    for (k, v) in keys {
        let ku = k.to_ascii_uppercase();
        let denied = __NYX_DENY_SUBSTRINGS.iter().any(|n| ku.contains(n));
        let val = if denied { __NYX_REDACTED } else { v.as_str() };
        if !first { out.push(','); }
        first = false;
        out.push('"');
        __nyx_esc(&k, &mut out);
        out.push_str("\":\"");
        __nyx_esc(val, &mut out);
        out.push('"');
    }
    out.push_str("},\"cwd\":\"");
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    __nyx_esc(&cwd, &mut out);
    out.push_str("\",\"payload_bytes\":[");
    let payload = std::env::var("NYX_PAYLOAD").unwrap_or_default();
    let bytes = payload.as_bytes();
    let cap = bytes.len().min(__NYX_PAYLOAD_LIMIT);
    for i in 0..cap {
        if i > 0 { out.push(','); }
        out.push_str(&format!("{}", bytes[i]));
    }
    out.push_str("],\"callee\":\"");
    __nyx_esc(sink_callee, &mut out);
    out.push_str("\",\"args_repr\":[");
    for (i, a) in args.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('"');
        __nyx_esc(a, &mut out);
        out.push('"');
    }
    out.push_str("]}");
    out
}

#[allow(dead_code)]
fn __nyx_emit(line: &str) {
    use std::io::Write;
    let p = match std::env::var("NYX_PROBE_PATH") {
        Ok(v) => v,
        Err(_) => return,
    };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
    {
        let _ = f.write_all(line.as_bytes());
        let _ = f.write_all(b"\n");
    }
}

#[allow(dead_code)]
fn __nyx_probe(sink_callee: &str, args: &[&str]) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let payload_id = std::env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let mut line = String::with_capacity(256);
    line.push_str("{\"sink_callee\":\"");
    __nyx_esc(sink_callee, &mut line);
    line.push_str("\",\"args\":[");
    for (i, a) in args.iter().enumerate() {
        if i > 0 { line.push(','); }
        line.push_str("{\"kind\":\"String\",\"value\":\"");
        __nyx_esc(a, &mut line);
        line.push_str("\"}");
    }
    line.push_str(&format!(
        "],\"captured_at_ns\":{},\"payload_id\":\"",
        now
    ));
    __nyx_esc(&payload_id, &mut line);
    line.push_str("\",\"kind\":{\"kind\":\"Normal\"},\"witness\":");
    line.push_str(&__nyx_witness_json(sink_callee, args));
    line.push('}');
    __nyx_emit(&line);
}

// Phase 08: install a sink-site signal handler via `libc::sigaction` so a
// SIGSEGV / SIGABRT / etc. inside the sink call is captured as a Crash
// probe before the kernel re-delivers it via SIG_DFL.  The shim is
// no-op on non-Unix targets (the dynamic-verification supported set is
// Unix-only) so consumers can splice it unconditionally.
#[cfg(unix)]
#[allow(dead_code)]
fn __nyx_install_crash_guard(sink_callee: &'static str) {
    use std::sync::atomic::{AtomicPtr, Ordering};
    static SINK_CALLEE: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
    SINK_CALLEE.store(sink_callee.as_ptr() as *mut u8, Ordering::SeqCst);
    let len = sink_callee.len();
    static CALLEE_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    CALLEE_LEN.store(len, Ordering::SeqCst);
    extern "C" fn handler(sig: i32) {
        // async-signal-unsafe code is unavoidable here (file I/O); we
        // accept the risk because the process is already dying and we
        // need the forensic record.
        let name = match sig {
            libc::SIGSEGV => "SIGSEGV",
            libc::SIGABRT => "SIGABRT",
            libc::SIGBUS => "SIGBUS",
            libc::SIGFPE => "SIGFPE",
            libc::SIGILL => "SIGILL",
            _ => "SIGABRT",
        };
        let p = SINK_CALLEE.load(Ordering::SeqCst);
        let len = CALLEE_LEN.load(Ordering::SeqCst);
        let sink_callee: &str = unsafe {
            if p.is_null() {
                ""
            } else {
                let slice = std::slice::from_raw_parts(p as *const u8, len);
                std::str::from_utf8_unchecked(slice)
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let payload_id = std::env::var("NYX_PAYLOAD_ID").unwrap_or_default();
        let mut line = String::with_capacity(256);
        line.push_str("{\"sink_callee\":\"");
        __nyx_esc(sink_callee, &mut line);
        line.push_str("\",\"args\":[],\"captured_at_ns\":");
        line.push_str(&format!("{now},\"payload_id\":\""));
        __nyx_esc(&payload_id, &mut line);
        line.push_str("\",\"kind\":{\"kind\":\"Crash\",\"signal\":\"");
        line.push_str(name);
        line.push_str("\"},\"witness\":");
        line.push_str(&__nyx_witness_json(sink_callee, &[]));
        line.push('}');
        __nyx_emit(&line);
        // Restore default handler and re-raise so process actually dies.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
            libc::raise(sig);
        }
    }
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in [libc::SIGSEGV, libc::SIGABRT, libc::SIGBUS, libc::SIGFPE, libc::SIGILL] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn __nyx_install_crash_guard(_sink_callee: &'static str) {}

// Phase 10 (Track D.3) SQL recording helper.  Mirrors the
// Python/Node/PHP/Go/Ruby/Java siblings: when the verifier spawned a
// SqlStub it publishes the side-channel log path on `NYX_SQL_LOG`; a
// sink callsite whose query never reaches the on-the-wire SQLite
// engine can call this helper to surface the attempted query.  Hash-
// prefixed detail lines followed by the query line so the host-side
// merger parses every language stream identically.  No-op when the
// env var is unset.
#[allow(dead_code)]
fn __nyx_stub_sql_record(query: &str, detail: &[(&str, &str)]) {
    use std::io::Write;
    let path = match std::env::var("NYX_SQL_LOG") {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut buf = String::with_capacity(128);
    for (k, v) in detail {
        buf.push_str("# ");
        buf.push_str(k);
        buf.push_str(": ");
        buf.push_str(v);
        buf.push('\n');
    }
    buf.push_str(query);
    if !query.ends_with('\n') {
        buf.push('\n');
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(buf.as_bytes());
    }
}

// Phase 10 (Track D.3) HTTP recording helper.  When the verifier
// spawned an HttpStub it publishes the side-channel log path on
// `NYX_HTTP_LOG`; a sink callsite whose outbound request never
// reaches the on-the-wire listener (DNS-mocked, network-isolated
// sandbox, pre-flight check) can call this helper to surface the
// attempted call.  Format matches the SQL helper so the host-side
// merger parses both streams identically.  No-op when the env var
// is unset.
#[allow(dead_code)]
fn __nyx_stub_http_record(method: &str, url: &str, body: Option<&str>, detail: &[(&str, &str)]) {
    use std::io::Write;
    let path = match std::env::var("NYX_HTTP_LOG") {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut buf = String::with_capacity(128);
    buf.push_str("# method: ");
    buf.push_str(method);
    buf.push('\n');
    buf.push_str("# url: ");
    buf.push_str(url);
    buf.push('\n');
    if let Some(b) = body {
        buf.push_str("# body: ");
        buf.push_str(b);
        buf.push('\n');
    }
    for (k, v) in detail {
        buf.push_str("# ");
        buf.push_str(k);
        buf.push_str(": ");
        buf.push_str(v);
        buf.push('\n');
    }
    buf.push_str(method);
    buf.push(' ');
    buf.push_str(url);
    buf.push('\n');
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(buf.as_bytes());
    }
}
"##
}

// ── Phase 16: shape detector ─────────────────────────────────────────────────

/// Concrete per-file shape resolved by reading the entry source.
///
/// One harness template per variant.  When the entry file is unreadable
/// or no marker fires the detector defaults to [`RustShape::Generic`],
/// preserving the pre-Phase-16 behaviour (direct `entry::func(payload)`
/// call).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustShape {
    /// `actix_web` handler — `async fn handler(req: HttpRequest) -> HttpResponse`
    /// or similar.  Harness drives the handler via a synchronous tokio
    /// runtime + mock `HttpRequest`.
    ActixWebRoute,
    /// Phase 17 — Track L.15.  `actix_web` handler bound through an
    /// `#[get("/path")]` / `#[post("/path")]` attribute macro.
    /// Emits a `NYX_ACTIX_TEST=1` toolchain marker on stdout so the
    /// verifier can confirm the framework dispatcher fired; v1
    /// dispatch re-uses the [`Self::ActixWebRoute`] in-process
    /// invocation pattern.
    ActixRoute,
    /// `axum` handler — `async fn handler(...) -> impl IntoResponse`.
    /// Harness invokes the handler with a synthesised payload-bearing
    /// argument under a tokio runtime.
    AxumHandler,
    /// Phase 17 — Track L.15.  `axum::Router.route("/path", get(handler))`
    /// route-bound handler.  Emits a `NYX_AXUM_TEST=1` marker.
    AxumRoute,
    /// Phase 17 — Track L.15.  Rocket `#[get("/path")]` attribute
    /// macro + `routes![...]` mount.  Emits a `NYX_ROCKET_TEST=1`
    /// marker.
    RocketRoute,
    /// Phase 17 — Track L.15.  Warp `warp::path!("users" / u32)`
    /// chained with `.map(...)` / `.and_then(...)`.  Emits a
    /// `NYX_WARP_TEST=1` marker.
    WarpRoute,
    /// clap-driven CLI: `entry` parses `std::env::args` via `clap`.
    /// Harness sets `std::env::args` (by overriding via `args_from`) and
    /// calls the entry function.
    ClapCli,
    /// libfuzzer target — `fuzz_target!(|data: &[u8]| { entry(data); })`
    /// or `pub fn entry(data: &[u8])` with libfuzzer-style signature.
    /// Harness invokes with `payload.as_bytes()`.
    LibfuzzerTarget,
    /// Plain free function — `fn entry(payload: &str)`.  Pre-Phase-16 default.
    Generic,
}

impl RustShape {
    /// Detect the shape from `(spec, source)`.  `source` is the literal
    /// bytes of the entry file (best-effort — empty string falls back
    /// to [`Self::Generic`]).
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let kind = spec.entry_kind.tag();
        let entry = spec.entry_name.as_str();

        let has_warp = source.contains("use warp::")
            || source.contains("warp::path!")
            || source.contains("warp::Filter")
            || source.contains("warp::serve")
            || source.contains("// nyx-shape: warp");
        let has_rocket = source.contains("use rocket::")
            || source.contains("rocket::routes")
            || source.contains("#[launch]")
            || source.contains("// nyx-shape: rocket");
        let has_actix_strong = source.contains("use actix_web")
            || source.contains("actix_web::")
            || source.contains("// nyx-shape: actix");
        let has_axum_strong = source.contains("use axum::")
            || source.contains("axum::Router")
            || source.contains("axum::routing")
            || source.contains("// nyx-shape: axum");
        let has_attribute_route = source.contains("#[get(")
            || source.contains("#[post(")
            || source.contains("#[put(")
            || source.contains("#[patch(")
            || source.contains("#[delete(");
        let has_clap = source.contains("clap::")
            || source.contains("#[derive(Parser)")
            || source.contains("Parser::parse");
        let has_libfuzzer = source.contains("libfuzzer_sys::fuzz_target")
            || source.contains("fuzz_target!")
            || (source.contains("pub fn ") && source.contains("data: &[u8]"));

        // Phase 17 framework variants win over the pre-Phase-16 weak
        // detectors.  Order: warp / rocket → actix → axum (warp and
        // rocket markers are uniquely identifying; actix and axum
        // share the bare attribute-macro syntax with rocket so they
        // come last).
        if has_warp {
            return Self::WarpRoute;
        }
        if has_rocket {
            return Self::RocketRoute;
        }
        if has_actix_strong {
            return if has_attribute_route {
                Self::ActixRoute
            } else {
                Self::ActixWebRoute
            };
        }
        if has_axum_strong {
            return Self::AxumRoute;
        }
        // Legacy weak detectors: HttpResponse / IntoResponse may
        // appear in code that does not import a known framework.
        let has_actix_weak = source.contains("HttpResponse") || source.contains("HttpRequest");
        let has_axum_weak = source.contains("IntoResponse")
            || source.contains("Json(")
            || source.contains("Query(");
        if has_axum_weak {
            return Self::AxumHandler;
        }
        if has_actix_weak || has_attribute_route {
            return Self::ActixWebRoute;
        }
        if has_clap {
            return Self::ClapCli;
        }
        if has_libfuzzer && (entry.starts_with("fuzz") || entry == "fuzz_target") {
            return Self::LibfuzzerTarget;
        }
        match kind {
            EntryKindTag::HttpRoute => Self::ActixWebRoute,
            EntryKindTag::CliSubcommand => Self::ClapCli,
            EntryKindTag::LibraryApi => Self::LibfuzzerTarget,
            _ => Self::Generic,
        }
    }
}

/// Public wrapper to detect the shape for a finalised `HarnessSpec`,
/// reading the entry file from disk.
pub fn detect_shape(spec: &HarnessSpec) -> RustShape {
    let src = read_entry_source(&spec.entry_file);
    RustShape::detect(spec, &src)
}

/// Phase 08 — Track J.6 header-injection harness for Rust
/// (`axum`-style `HeaderMap::insert`).
///
/// Tier (a): when the fixture imports `axum::http::HeaderMap`, rewrite
/// the axum imports to point at a local `nyx_harness_stubs` module
/// shipped in `src/nyx_harness_stubs.rs`, stage the rewritten fixture
/// at `src/entry.rs` via `extra_files`, and have main.rs declare
/// `mod entry;` + `mod nyx_harness_stubs;` so the fixture's real
/// `headers.insert(...)` call site runs through a permissive stub that
/// records every captured `(name, value)` pair (modern `http >= 0.2`
/// rejects raw `\r\n` in `HeaderValue::from_bytes`, so a real-axum
/// build would panic on the vuln payload before the differential
/// oracle sees the smuggled header).
///
/// Tier (b) — raw-socket wire frame: when the fixture uses
/// `std::net::TcpListener::bind` (the `rust_raw` fixture exports
/// `create_server` + `run_once` + `set_cookie_value`), boot the
/// listener on a loopback port via the fixture, open a `TcpStream`
/// from the harness, read the bytes the fixture wrote to the response
/// socket up to the `\r\n\r\n` boundary, and emit them as a
/// `ProbeKind::HeaderWireFrame` record.  Bypasses every framework-
/// level CRLF validator since the fixture owns the write path.
///
/// Tier (c) synthetic fallback: when the fixture imports neither
/// axum nor TcpListener, fall back to the synthetic
/// `nyx_header_probe("Set-Cookie", &payload)` call so the differential
/// oracle still flips on raw payload bytes.
pub fn emit_header_injection_harness(spec: &HarnessSpec) -> HarnessSource {
    let entry_source = read_entry_source(&spec.entry_file);
    if entry_source_uses_raw_socket(&entry_source) {
        return emit_header_injection_wire_frame_harness(spec, &entry_source);
    }
    let shim = probe_shim();
    let tier_a_active = entry_source_imports_axum_header(&entry_source);
    let entry_fn = &spec.entry_name;
    let needs_percent_encoding = entry_source.contains("percent_encoding");

    let mut mod_decls = String::new();
    let mut via_fixture_decl = String::new();
    let via_fixture_invoke;
    let mut extra_files: Vec<(String, String)> = Vec::new();
    let mut entry_subpath: Option<String> = Some("src/entry.rs".into());

    if tier_a_active {
        let rewritten = rewrite_axum_imports(&entry_source);
        extra_files.push(("src/entry.rs".into(), rewritten));
        extra_files.push((
            "src/nyx_harness_stubs.rs".into(),
            rust_header_stubs_source().to_owned(),
        ));
        // Park the raw fixture out of `src/` so its un-rewritten axum
        // imports don't reach the compiler.  Nothing references the
        // path, so cargo ignores the file.
        entry_subpath = Some("ignored/raw_fixture.rs".into());
        mod_decls.push_str("mod entry;\nmod nyx_harness_stubs;\n");
        via_fixture_decl = format!(
            r##"fn nyx_header_via_fixture(payload: &str) -> bool {{
    use std::panic;
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {{
        let mut headers = nyx_harness_stubs::HeaderMap::new();
        entry::{entry_fn}(&mut headers, payload);
        let mut fired = false;
        for (name, value) in headers.iter() {{
            nyx_header_probe(name, &value);
            fired = true;
        }}
        fired
    }}));
    result.unwrap_or(false)
}}

"##
        );
        via_fixture_invoke = "    if !nyx_header_via_fixture(&payload) {\n        nyx_header_probe(\"Set-Cookie\", &payload);\n    }\n".to_owned();
    } else {
        via_fixture_invoke = "    nyx_header_probe(\"Set-Cookie\", &payload);\n".to_owned();
    }

    let cargo_toml = generate_cargo_toml_with_extras(Cap::HEADER_INJECTION, needs_percent_encoding);
    extra_files.insert(0, ("Cargo.toml".into(), cargo_toml));

    let main_rs = format!(
        r##"//! Nyx dynamic harness — HEADER_INJECTION HeaderMap::insert (Phase 08 / Track J.6).
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{{SystemTime, UNIX_EPOCH}};

{mod_decls}{shim}

fn nyx_json_escape(s: &str) -> String {{
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {{
        match c {{
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {{
                out.push_str(&format!("\\u{{:04x}}", c as u32));
            }}
            c => out.push(c),
        }}
    }}
    out
}}

fn nyx_header_probe(name: &str, value: &str) {{
    let p = match env::var("NYX_PROBE_PATH") {{ Ok(s) => s, Err(_) => return }};
    if p.is_empty() {{ return; }}
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    let pid = env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let mut line = String::new();
    line.push_str("{{\"sink_callee\":\"HeaderMap::insert\",\"args\":[");
    line.push_str("{{\"kind\":\"String\",\"value\":\"");
    line.push_str(&nyx_json_escape(name));
    line.push_str("\"}},{{\"kind\":\"String\",\"value\":\"");
    line.push_str(&nyx_json_escape(value));
    line.push_str("\"}}],");
    line.push_str("\"captured_at_ns\":");
    line.push_str(&now.to_string());
    line.push_str(",\"payload_id\":\"");
    line.push_str(&nyx_json_escape(&pid));
    line.push_str("\",\"kind\":{{\"kind\":\"HeaderEmit\",\"name\":\"");
    line.push_str(&nyx_json_escape(name));
    line.push_str("\",\"value\":\"");
    line.push_str(&nyx_json_escape(value));
    line.push_str("\",\"protocol\":\"in-process\"}},\"witness\":{{}}}}\n");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {{
        let _ = f.write_all(line.as_bytes());
    }}
}}

{via_fixture_decl}fn main() {{
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
{via_fixture_invoke}    println!("__NYX_SINK_HIT__");
    let mut body = String::new();
    body.push_str("{{\"payload_len\":");
    body.push_str(&payload.len().to_string());
    body.push_str("}}");
    println!("{{body}}", body = body);
}}
"##
    );
    HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files,
        entry_subpath,
    }
}

/// Tier-(a) gate for HEADER_INJECTION: the fixture imports the
/// `axum::http::HeaderMap` type.  Matches both the explicit `use`
/// form and the path-qualified form (`axum::http::HeaderMap` token).
fn entry_source_imports_axum_header(src: &str) -> bool {
    src.contains("axum::http::HeaderMap") || src.contains("http::HeaderMap")
}

/// Tier-(b) wire-frame gate for HEADER_INJECTION.  Fires when the
/// fixture binds a raw `std::net::TcpListener` and exposes the
/// `set_cookie_value` / `create_server` / `run_once` triple the harness
/// drives.  Distinct from the axum gate because the wire-frame branch
/// owns the response-write path itself and bypasses every framework
/// CRLF validator.
fn entry_source_uses_raw_socket(src: &str) -> bool {
    src.contains("TcpListener::bind") && src.contains("set_cookie_value")
}

/// Tier-(b) wire-frame harness for HEADER_INJECTION (Phase 08 / Track
/// J.6).  Stages the raw-socket fixture at `src/entry.rs`, declares
/// `mod entry;` in `main.rs`, and drives the fixture's `create_server`
/// and `run_once` API in a worker thread while the harness opens a
/// `TcpStream` against the bound port, issues one `GET / HTTP/1.0`,
/// and reads the bytes the fixture wrote to the response socket up to
/// the `\r\n\r\n` boundary.  The captured header block is emitted as a
/// `ProbeKind::HeaderWireFrame` probe; per-`Set-Cookie` lines are also
/// emitted as `ProbeKind::HeaderEmit` records so the tier-(a)
/// `HeaderInjected` predicate fires on the same pass.  Prints a
/// `wire_frame_len` stdout marker so e2e tests can pin the branch.
fn emit_header_injection_wire_frame_harness(
    _spec: &HarnessSpec,
    entry_source: &str,
) -> HarnessSource {
    let shim = probe_shim();
    let needs_percent_encoding = entry_source.contains("percent_encoding");
    let mut extra_files: Vec<(String, String)> = Vec::new();
    let cargo_toml = generate_cargo_toml_with_extras(Cap::HEADER_INJECTION, needs_percent_encoding);
    extra_files.push(("Cargo.toml".into(), cargo_toml));

    let main_rs = format!(
        r##"//! Nyx dynamic harness — HEADER_INJECTION raw-socket wire frame (Phase 08 / Track J.6).
mod entry;
use std::env;
use std::fs::OpenOptions;
use std::io::{{Read, Write}};
use std::net::TcpStream;
use std::thread;
use std::time::{{Duration, SystemTime, UNIX_EPOCH}};

{shim}

fn nyx_json_escape(s: &str) -> String {{
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {{
        match c {{
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {{
                out.push_str(&format!("\\u{{:04x}}", c as u32));
            }}
            c => out.push(c),
        }}
    }}
    out
}}

fn nyx_byte_list(bytes: &[u8]) -> String {{
    let mut out = String::with_capacity(bytes.len() * 4 + 2);
    out.push('[');
    for (i, b) in bytes.iter().enumerate() {{
        if i > 0 {{ out.push(','); }}
        out.push_str(&b.to_string());
    }}
    out.push(']');
    out
}}

fn nyx_emit_record(line: &str) {{
    let p = match env::var("NYX_PROBE_PATH") {{ Ok(s) => s, Err(_) => return }};
    if p.is_empty() {{ return; }}
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {{
        let _ = f.write_all(line.as_bytes());
    }}
}}

fn nyx_now_ns() -> u64 {{
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}}

fn nyx_header_probe(name: &str, value: &str) {{
    let now = nyx_now_ns();
    let pid = env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let mut line = String::new();
    line.push_str("{{\"sink_callee\":\"TcpStream::write_all\",\"args\":[");
    line.push_str("{{\"kind\":\"String\",\"value\":\"");
    line.push_str(&nyx_json_escape(name));
    line.push_str("\"}},{{\"kind\":\"String\",\"value\":\"");
    line.push_str(&nyx_json_escape(value));
    line.push_str("\"}}],");
    line.push_str("\"captured_at_ns\":");
    line.push_str(&now.to_string());
    line.push_str(",\"payload_id\":\"");
    line.push_str(&nyx_json_escape(&pid));
    line.push_str("\",\"kind\":{{\"kind\":\"HeaderEmit\",\"name\":\"");
    line.push_str(&nyx_json_escape(name));
    line.push_str("\",\"value\":\"");
    line.push_str(&nyx_json_escape(value));
    line.push_str("\",\"protocol\":\"wire\"}},\"witness\":{{}}}}\n");
    nyx_emit_record(&line);
}}

fn nyx_wire_frame_probe(raw_bytes: &[u8]) {{
    let now = nyx_now_ns();
    let pid = env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let mut line = String::new();
    line.push_str("{{\"sink_callee\":\"TcpStream::write_all\",\"args\":[],");
    line.push_str("\"captured_at_ns\":");
    line.push_str(&now.to_string());
    line.push_str(",\"payload_id\":\"");
    line.push_str(&nyx_json_escape(&pid));
    line.push_str("\",\"kind\":{{\"kind\":\"HeaderWireFrame\",\"raw_bytes\":");
    line.push_str(&nyx_byte_list(raw_bytes));
    line.push_str("}},\"witness\":{{}}}}\n");
    nyx_emit_record(&line);
}}

fn nyx_wire_frame_via_fixture(payload: &str) -> Option<Vec<u8>> {{
    // Phase 08 tier-(b): install the cookie value on the fixture, boot
    // its `TcpListener` on 127.0.0.1:0, drive `run_once` on a worker
    // thread, then issue one raw-socket GET from the harness and read
    // the bytes the fixture wrote to the response socket up to the
    // CRLF-CRLF boundary.  Returns None on connect / read failure so
    // the caller can fall back to the synthetic probe.
    entry::set_cookie_value(payload.as_bytes());
    let listener = match std::panic::catch_unwind(entry::create_server) {{
        Ok(listener) => listener,
        Err(_) => return Some(nyx_fallback_wire_frame(payload)),
    }};
    let addr = match listener.local_addr() {{
        Ok(a) => a,
        Err(_) => return Some(nyx_fallback_wire_frame(payload)),
    }};
    let handle = thread::spawn(move || entry::run_once(listener));
    let mut client = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {{
        Ok(c) => c,
        Err(_) => {{
            let _ = handle.join();
            return Some(nyx_fallback_wire_frame(payload));
        }}
    }};
    let _ = client.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(2)));
    if client
        .write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .is_err()
    {{
        let _ = handle.join();
        return Some(nyx_fallback_wire_frame(payload));
    }}
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    while raw.len() < 65536 {{
        match client.read(&mut buf) {{
            Ok(0) => break,
            Ok(n) => {{
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {{
                    break;
                }}
            }}
            Err(_) => break,
        }}
    }}
    let _ = handle.join();
    if raw.is_empty() {{
        return Some(nyx_fallback_wire_frame(payload));
    }}
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    Some(raw[..sep].to_vec())
}}

fn nyx_fallback_wire_frame(payload: &str) -> Vec<u8> {{
    let body = b"ok\n";
    let mut raw = Vec::new();
    raw.extend_from_slice(b"HTTP/1.0 200 OK\r\n");
    raw.extend_from_slice(format!("Content-Length: {{}}\r\n", body.len()).as_bytes());
    raw.extend_from_slice(b"Set-Cookie: ");
    raw.extend_from_slice(payload.as_bytes());
    raw
}}

fn main() {{
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
    if let Some(raw_bytes) = nyx_wire_frame_via_fixture(&payload) {{
        nyx_wire_frame_probe(&raw_bytes);
        // Derive HeaderEmit records per Set-Cookie line on the wire so
        // the tier-(a) HeaderInjected predicate also fires on the same
        // harness pass.  The wire-frame branch owns the bytes; the
        // HeaderEmit records are derived from them.
        for line in raw_bytes.split(|&b| b == b'\n') {{
            let trimmed: &[u8] = if line.last() == Some(&b'\r') {{
                &line[..line.len() - 1]
            }} else {{
                line
            }};
            let sep = match trimmed.iter().position(|&b| b == b':') {{
                Some(s) => s,
                None => continue,
            }};
            let name = match std::str::from_utf8(&trimmed[..sep]) {{
                Ok(s) => s,
                Err(_) => continue,
            }};
            if !name.eq_ignore_ascii_case("Set-Cookie") {{
                continue;
            }}
            let mut start = sep + 1;
            if start < trimmed.len() && trimmed[start] == b' ' {{
                start += 1;
            }}
            let value = String::from_utf8_lossy(&trimmed[start..]).into_owned();
            nyx_header_probe(name, &value);
        }}
        println!("__NYX_SINK_HIT__");
        println!("{{{{\"wire_frame_len\":{{}}}}}}", raw_bytes.len());
        return;
    }}
    // Synthetic fallback when the fixture failed to boot — keeps the
    // differential oracle live on a build/boot failure rather than
    // silently shedding the attempt.
    nyx_header_probe("Set-Cookie", &payload);
    println!("__NYX_SINK_HIT__");
    println!("{{{{\"payload_len\":{{}}}}}}", payload.len());
}}
"##
    );

    HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files,
        entry_subpath: Some("src/entry.rs".into()),
    }
}

/// Tier-(a) gate for OPEN_REDIRECT: the fixture imports
/// `axum::response::Redirect`.
fn entry_source_imports_axum_redirect(src: &str) -> bool {
    src.contains("axum::response::Redirect") || src.contains("response::Redirect")
}

/// Rewrite axum import paths at emit time so the fixture compiles
/// against the local `nyx_harness_stubs` module instead of the real
/// axum / http crates.  Three substitutions are applied:
///
/// - `axum::http::HeaderMap` → `crate::nyx_harness_stubs::HeaderMap`
/// - `axum::http::HeaderValue` → `crate::nyx_harness_stubs::HeaderValue`
/// - `axum::response::Redirect` → `crate::nyx_harness_stubs::Redirect`
///
/// The substitutions are byte-level and idempotent; un-matched files
/// pass through unchanged.
fn rewrite_axum_imports(src: &str) -> String {
    src.replace(
        "axum::http::HeaderMap",
        "crate::nyx_harness_stubs::HeaderMap",
    )
    .replace(
        "axum::http::HeaderValue",
        "crate::nyx_harness_stubs::HeaderValue",
    )
    .replace(
        "axum::response::Redirect",
        "crate::nyx_harness_stubs::Redirect",
    )
}

/// Source for the `nyx_harness_stubs` module — permissive stand-ins
/// for `axum::http::{HeaderMap, HeaderValue}` that record raw header
/// bytes (including CRLF) without invoking the real `http` crate's
/// RFC-7230 value validator.  The real axum / http crates reject raw
/// `\r\n` in `HeaderValue::from_bytes`, which would mask the vuln
/// fixture's smuggled header before the differential oracle sees it.
fn rust_header_stubs_source() -> &'static str {
    r##"//! Permissive axum::http stubs — record header bytes verbatim.
#![allow(dead_code)]

pub struct HeaderValue {
    bytes: Vec<u8>,
}

impl HeaderValue {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        Ok(Self { bytes: bytes.to_vec() })
    }

    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        Ok(Self { bytes: s.as_bytes().to_vec() })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct HeaderMap {
    items: Vec<(String, Vec<u8>)>,
}

impl Default for HeaderMap {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderMap {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn insert<K: Into<String>>(&mut self, key: K, value: HeaderValue) -> Option<HeaderValue> {
        self.items.push((key.into(), value.bytes));
        None
    }

    pub fn iter(&self) -> HeaderMapIter<'_> {
        HeaderMapIter { inner: self.items.iter() }
    }
}

pub struct HeaderMapIter<'a> {
    inner: std::slice::Iter<'a, (String, Vec<u8>)>,
}

impl<'a> Iterator for HeaderMapIter<'a> {
    type Item = (&'a str, String);
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| {
            (k.as_str(), String::from_utf8_lossy(v).into_owned())
        })
    }
}

pub struct Redirect {
    location: String,
}

impl Redirect {
    pub fn to(s: &str) -> Self {
        Self { location: s.to_owned() }
    }

    pub fn location(&self) -> &str {
        &self.location
    }
}
"##
}

/// Phase 09 — Track J.7 open-redirect harness for Rust
/// (`axum::response::Redirect::to`).
///
/// Tier (a): when the fixture imports `axum::response::Redirect`,
/// rewrite the axum import to point at the local
/// `nyx_harness_stubs::Redirect` shim, stage the rewritten fixture at
/// `src/entry.rs` via `extra_files`, declare `mod entry;` +
/// `mod nyx_harness_stubs;` in main.rs, invoke `entry::<fn>(payload)`,
/// read the captured `Location:` value off the returned stub and emit
/// a `ProbeKind::Redirect` probe carrying it.
///
/// Tier (b): when the fixture does not import axum, fall back to the
/// synthetic `nyx_redirect_probe(payload, "example.com")` call so the
/// differential oracle still flips on raw payload bytes.
pub fn emit_open_redirect_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let tier_a_active = entry_source_imports_axum_redirect(&entry_source);
    let entry_fn = &spec.entry_name;

    let mut mod_decls = String::new();
    let mut via_fixture_decl = String::new();
    let via_fixture_invoke;
    let mut extra_files: Vec<(String, String)> = Vec::new();
    let mut entry_subpath: Option<String> = Some("src/entry.rs".into());

    if tier_a_active {
        let rewritten = rewrite_axum_imports(&entry_source);
        extra_files.push(("src/entry.rs".into(), rewritten));
        extra_files.push((
            "src/nyx_harness_stubs.rs".into(),
            rust_header_stubs_source().to_owned(),
        ));
        entry_subpath = Some("ignored/raw_fixture.rs".into());
        mod_decls.push_str("mod entry;\nmod nyx_harness_stubs;\n");
        via_fixture_decl = format!(
            r##"fn nyx_redirect_via_fixture(payload: String) -> Option<String> {{
    use std::panic;
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {{
        let redirect = entry::{entry_fn}(payload);
        redirect.location().to_owned()
    }}));
    result.ok()
}}

"##
        );
        via_fixture_invoke = "    let location = match nyx_redirect_via_fixture(payload.clone()) {\n        Some(loc) if !loc.is_empty() => loc,\n        _ => payload.clone(),\n    };\n    nyx_redirect_probe(&location, request_host);\n    nyx_follow_location(&location);\n".to_owned();
    } else {
        via_fixture_invoke = "    let location = payload.clone();\n    nyx_redirect_probe(&location, request_host);\n    nyx_follow_location(&location);\n".to_owned();
    }

    let cargo_toml = generate_cargo_toml(Cap::OPEN_REDIRECT);
    extra_files.insert(0, ("Cargo.toml".into(), cargo_toml));

    let main_rs = format!(
        r##"//! Nyx dynamic harness — OPEN_REDIRECT Redirect::to (Phase 09 / Track J.7).
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{{SystemTime, UNIX_EPOCH}};

{mod_decls}{shim}

fn nyx_json_escape(s: &str) -> String {{
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {{
        match c {{
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {{
                out.push_str(&format!("\\u{{:04x}}", c as u32));
            }}
            c => out.push(c),
        }}
    }}
    out
}}

fn nyx_redirect_probe(location: &str, request_host: &str) {{
    let p = match env::var("NYX_PROBE_PATH") {{ Ok(s) => s, Err(_) => return }};
    if p.is_empty() {{ return; }}
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    let pid = env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let mut line = String::new();
    line.push_str("{{\"sink_callee\":\"Redirect::to\",\"args\":[");
    line.push_str("{{\"kind\":\"String\",\"value\":\"");
    line.push_str(&nyx_json_escape(location));
    line.push_str("\"}}],");
    line.push_str("\"captured_at_ns\":");
    line.push_str(&now.to_string());
    line.push_str(",\"payload_id\":\"");
    line.push_str(&nyx_json_escape(&pid));
    line.push_str("\",\"kind\":{{\"kind\":\"Redirect\",\"location\":\"");
    line.push_str(&nyx_json_escape(location));
    line.push_str("\",\"request_host\":\"");
    line.push_str(&nyx_json_escape(request_host));
    line.push_str("\"}},\"witness\":{{}}}}\n");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {{
        let _ = f.write_all(line.as_bytes());
    }}
}}

// Phase 09 OOB closure: when the captured Location is a loopback URL,
// follow it with a zero-dep `TcpStream` GET so the OOB listener
// observes the per-finding nonce.  Skips non-loopback hosts and
// non-HTTP schemes (no real network egress).  Best-effort: errors do
// not propagate; the listener may still record the TCP connect before
// the read fails.
fn nyx_follow_location(location: &str) {{
    if location.is_empty() {{ return; }}
    let loopback = location.starts_with("http://127.0.0.1")
        || location.starts_with("http://localhost")
        || location.starts_with("http://host-gateway");
    if !loopback {{ return; }}
    let rest = match location.strip_prefix("http://") {{
        Some(r) => r,
        None => return,
    }};
    let (authority, path) = match rest.find('/') {{
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    }};
    let (host, port): (&str, u16) = match authority.rfind(':') {{
        Some(i) => {{
            let p = authority[i + 1..].parse::<u16>().unwrap_or(80);
            (&authority[..i], p)
        }}
        None => (authority, 80),
    }};
    use std::io::{{Read, Write}};
    use std::net::{{TcpStream, ToSocketAddrs}};
    use std::time::Duration;
    let addr = match (host, port).to_socket_addrs() {{
        Ok(mut it) => match it.next() {{ Some(a) => a, None => return }},
        Err(_) => return,
    }};
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {{
        Ok(s) => s,
        Err(_) => return,
    }};
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let req = format!("GET {{path}} HTTP/1.0\r\nHost: {{host}}\r\nConnection: close\r\n\r\n", path = path, host = host);
    let _ = stream.write_all(req.as_bytes());
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf);
}}

{via_fixture_decl}fn main() {{
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
    let request_host = "example.com";
{via_fixture_invoke}    println!("__NYX_SINK_HIT__");
    let mut body = String::new();
    body.push_str("{{\"request_host\":\"");
    body.push_str(&nyx_json_escape(request_host));
    body.push_str("\"}}");
    println!("{{body}}", body = body);
}}
"##
    );
    HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files,
        entry_subpath,
    }
}

fn read_entry_source(entry_file: &str) -> String {
    let candidates = [
        PathBuf::from(entry_file),
        PathBuf::from(".").join(entry_file),
    ];
    for path in &candidates {
        if let Ok(s) = std::fs::read_to_string(path) {
            return s;
        }
    }
    String::new()
}

/// Phase 11 — Track J.9 CRYPTO weak-RNG harness for Rust.
///
/// Stages the fixture at `src/entry.rs`, builds against `rand = "0.8"`
/// (added to `Cargo.toml` automatically when `Cap::CRYPTO` is set —
/// see [`generate_cargo_toml_with_extras`]), invokes
/// `entry::<entry_name>(&payload)`, reduces the produced key into a
/// `u64` via the `NyxKeyToInt` trait, and writes a
/// `ProbeKind::WeakKey { key_int }` probe.
///
/// The `NyxKeyToInt` trait has impls for `u8` / `u16` / `u32` / `u64` /
/// `usize` / signed counterparts (masked to `i64::MAX` so the sign bit
/// does not flip a 16-bit predicate), `bool` (1/0), `[u8; N]`,
/// `Vec<u8>`, `String`, and `&str`.  Byte / string returns are left-
/// zero-padded to 8 bytes then read as big-endian `u64`, mirroring the
/// Python / Go / Java / PHP sibling reduction: a `rand::thread_rng()
/// .gen_range(0..=0xFFFF) as u16` vuln return lands in `[0, 65535]` and
/// trips the `WeakKeyEntropy { max_bits: 16 }` predicate; an
/// `OsRng.fill_bytes([u8; 32])` benign return's leading 8 bytes are
/// uniformly distributed across `u64::MAX` and overshoot the budget
/// with probability `1 - 2^-48` — effectively always.
pub fn emit_crypto_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_fn = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let cargo_toml = generate_cargo_toml(Cap::CRYPTO);

    let main_rs = format!(
        r##"//! Nyx dynamic harness — CRYPTO weak-RNG key entropy (Phase 11 / Track J.9).
mod entry;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{{SystemTime, UNIX_EPOCH}};

{shim}

/// Reduce the fixture's produced key to a `u64` the `WeakKey` probe
/// shape can carry verbatim.  Impls below cover the return types the
/// curated CRYPTO fixtures hand back; future fixtures returning other
/// shapes should grow an impl here rather than panicking at compile
/// time.
trait NyxKeyToInt {{
    fn to_key_int(self) -> u64;
}}

fn nyx_bytes_to_key_int(bytes: &[u8]) -> u64 {{
    // Left-zero-pad short slices then read the leading 8 bytes as
    // big-endian, mirroring PHP's `unpack('J', str_pad($head, 8,
    // "\\0", STR_PAD_LEFT))` and Go's `binary.BigEndian.Uint64` with
    // left zero-pad.
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    let start = 8 - n;
    buf[start..start + n].copy_from_slice(&bytes[..n]);
    u64::from_be_bytes(buf)
}}

impl NyxKeyToInt for u8 {{ fn to_key_int(self) -> u64 {{ u64::from(self) }} }}
impl NyxKeyToInt for u16 {{ fn to_key_int(self) -> u64 {{ u64::from(self) }} }}
impl NyxKeyToInt for u32 {{ fn to_key_int(self) -> u64 {{ u64::from(self) }} }}
impl NyxKeyToInt for u64 {{ fn to_key_int(self) -> u64 {{ self }} }}
impl NyxKeyToInt for usize {{ fn to_key_int(self) -> u64 {{ self as u64 }} }}
impl NyxKeyToInt for i8 {{ fn to_key_int(self) -> u64 {{ (self as u64) & (i64::MAX as u64) }} }}
impl NyxKeyToInt for i16 {{ fn to_key_int(self) -> u64 {{ (self as u64) & (i64::MAX as u64) }} }}
impl NyxKeyToInt for i32 {{ fn to_key_int(self) -> u64 {{ (self as u64) & (i64::MAX as u64) }} }}
impl NyxKeyToInt for i64 {{ fn to_key_int(self) -> u64 {{ (self as u64) & (i64::MAX as u64) }} }}
impl NyxKeyToInt for isize {{ fn to_key_int(self) -> u64 {{ (self as u64) & (i64::MAX as u64) }} }}
impl NyxKeyToInt for bool {{ fn to_key_int(self) -> u64 {{ if self {{ 1 }} else {{ 0 }} }} }}
impl<const N: usize> NyxKeyToInt for [u8; N] {{
    fn to_key_int(self) -> u64 {{ nyx_bytes_to_key_int(&self) }}
}}
impl NyxKeyToInt for Vec<u8> {{
    fn to_key_int(self) -> u64 {{ nyx_bytes_to_key_int(&self) }}
}}
impl NyxKeyToInt for String {{
    fn to_key_int(self) -> u64 {{ nyx_bytes_to_key_int(self.as_bytes()) }}
}}
impl<'a> NyxKeyToInt for &'a str {{
    fn to_key_int(self) -> u64 {{ nyx_bytes_to_key_int(self.as_bytes()) }}
}}

fn nyx_weak_key_probe(key_int: u64) {{
    let p = match env::var("NYX_PROBE_PATH") {{ Ok(s) => s, Err(_) => return }};
    if p.is_empty() {{ return; }}
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let payload_id = env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let key_str = key_int.to_string();
    let mut line = String::with_capacity(256);
    line.push_str("{{\"sink_callee\":\"__nyx_weak_key\",\"args\":[");
    line.push_str("{{\"kind\":\"Int\",\"value\":");
    line.push_str(&key_str);
    line.push_str("}}],");
    line.push_str("\"captured_at_ns\":");
    line.push_str(&now.to_string());
    line.push_str(",\"payload_id\":\"");
    let mut esc_pid = String::new();
    __nyx_esc(&payload_id, &mut esc_pid);
    line.push_str(&esc_pid);
    line.push_str("\",\"kind\":{{\"kind\":\"WeakKey\",\"key_int\":");
    line.push_str(&key_str);
    line.push_str("}},\"witness\":");
    line.push_str(&__nyx_witness_json("__nyx_weak_key", &[&key_str]));
    line.push_str("}}\n");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {{
        let _ = f.write_all(line.as_bytes());
    }}
}}

fn main() {{
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
    __nyx_install_crash_guard("__nyx_weak_key");
    let produced = entry::{entry_fn}(&payload);
    let key_int = produced.to_key_int();
    nyx_weak_key_probe(key_int);
    println!("__NYX_SINK_HIT__");
    println!("{{{{\"key_int\":{{key_int}}}}}}", key_int = key_int);
}}
"##
    );
    HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files: vec![("Cargo.toml".into(), cargo_toml)],
        entry_subpath: Some("src/entry.rs".into()),
    }
}

/// Phase 11 — Track J.9 JSON_PARSE depth-bomb harness for Rust.
///
/// Stages the fixture at `src/entry.rs`, builds against
/// `serde_json = "1"` (added to `Cargo.toml` automatically when
/// `Cap::JSON_PARSE` is set — see [`generate_cargo_toml_with_extras`]),
/// invokes `entry::<entry_name>(&payload)`, walks the returned
/// `serde_json::Value` iteratively, and writes a
/// `ProbeKind::JsonParse { depth, excessive_depth }` probe.
///
/// The fixture's entry is expected to return a `serde_json::Value`
/// (parsing `&str` / `&[u8]` via `serde_json::from_str` or
/// `serde_json::from_slice` and returning the resulting `Value`).
/// `serde_json` is iterative so deeply-nested input never panics the
/// parser; the harness reads the observed depth off the returned
/// value rather than intercepting the parse call site itself.
pub fn emit_json_parse_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_fn = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let cargo_toml = generate_cargo_toml(Cap::JSON_PARSE);

    let main_rs = format!(
        r##"//! Nyx dynamic harness — JSON_PARSE depth checks (Phase 11 / Track J.9).
mod entry;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{{SystemTime, UNIX_EPOCH}};

{shim}

const NYX_JSON_MAX_WALK: usize = 4096;

fn nyx_json_count_depth(value: &serde_json::Value) -> u32 {{
    let mut max_depth: u32 = 0;
    let mut stack: Vec<(&serde_json::Value, u32)> = Vec::with_capacity(64);
    stack.push((value, 1));
    let mut visited: usize = 0;
    while let Some((cur, depth)) = stack.pop() {{
        visited += 1;
        if visited > NYX_JSON_MAX_WALK {{ break; }}
        if depth > max_depth {{ max_depth = depth; }}
        match cur {{
            serde_json::Value::Array(items) => {{
                for child in items {{
                    stack.push((child, depth + 1));
                }}
            }}
            serde_json::Value::Object(map) => {{
                for child in map.values() {{
                    stack.push((child, depth + 1));
                }}
            }}
            _ => {{}}
        }}
    }}
    max_depth
}}

fn nyx_json_parse_probe(depth: u32, excessive: bool) {{
    let p = match env::var("NYX_PROBE_PATH") {{ Ok(s) => s, Err(_) => return }};
    if p.is_empty() {{ return; }}
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let payload_id = env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let depth_str = depth.to_string();
    let excessive_str = if excessive {{ "true" }} else {{ "false" }};
    let mut line = String::with_capacity(256);
    line.push_str("{{\"sink_callee\":\"serde_json::from_str\",\"args\":[");
    line.push_str("{{\"kind\":\"Int\",\"value\":");
    line.push_str(&depth_str);
    line.push_str("}}],");
    line.push_str("\"captured_at_ns\":");
    line.push_str(&now.to_string());
    line.push_str(",\"payload_id\":\"");
    let mut esc_pid = String::new();
    __nyx_esc(&payload_id, &mut esc_pid);
    line.push_str(&esc_pid);
    line.push_str("\",\"kind\":{{\"kind\":\"JsonParse\",\"depth\":");
    line.push_str(&depth_str);
    line.push_str(",\"excessive_depth\":");
    line.push_str(excessive_str);
    line.push_str("}},\"witness\":");
    line.push_str(&__nyx_witness_json("serde_json::from_str", &[&depth_str]));
    line.push_str("}}\n");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {{
        let _ = f.write_all(line.as_bytes());
    }}
}}

fn main() {{
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
    __nyx_install_crash_guard("serde_json::from_str");
    let parsed = entry::{entry_fn}(&payload);
    let depth = nyx_json_count_depth(&parsed);
    let excessive = depth > 64;
    nyx_json_parse_probe(depth, excessive);
    println!("__NYX_SINK_HIT__");
    println!("{{{{\"depth\":{{depth}}}}}}", depth = depth);
}}
"##
    );
    HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files: vec![("Cargo.toml".into(), cargo_toml)],
        entry_subpath: Some("src/entry.rs".into()),
    }
}

/// Phase 11 (Track J.9) UNAUTHORIZED_ID IDOR harness for Rust.
///
/// Stages the fixture at `src/entry.rs`, invokes
/// `entry::<entry_name>(&payload)` which is expected to return an
/// `Option<_>`, and emits a
/// [`crate::dynamic::probe::ProbeKind::IdorAccess`] probe iff the
/// fixture materialises a `Some(_)` record.  The
/// [`crate::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
/// predicate fires when `caller_id != owner_id`; the harness pins
/// `caller_id = "alice"` and treats the payload as `owner_id`.  Falls
/// back to a payload-only path that emits an
/// `IdorAccess(alice, payload)` probe when the fixture source is
/// unreachable so the universal sink-hit path still fires.
pub fn emit_unauthorized_id_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_fn = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let cargo_toml = generate_cargo_toml(Cap::UNAUTHORIZED_ID);
    let entry_source = read_entry_source(&spec.entry_file);
    let tier_a_active = !entry_source.is_empty();

    let (mod_decls, via_fixture_invoke, extra_files, entry_subpath) = if tier_a_active {
        let extras: Vec<(String, String)> = vec![
            ("Cargo.toml".into(), cargo_toml),
            ("src/entry.rs".into(), entry_source.clone()),
        ];
        let invoke = format!(
            "    let nyx_record = entry::{entry_fn}(&payload);\n    if nyx_record.is_some() {{\n        nyx_idor_access_probe(_NYX_CALLER_ID, &payload);\n    }}\n",
        );
        (
            "mod entry;\n".to_owned(),
            invoke,
            extras,
            Some("ignored/raw_fixture.rs".to_owned()),
        )
    } else {
        let extras: Vec<(String, String)> = vec![("Cargo.toml".into(), cargo_toml)];
        let invoke = "    nyx_idor_access_probe(_NYX_CALLER_ID, &payload);\n".to_owned();
        (
            String::new(),
            invoke,
            extras,
            Some("ignored/raw_fixture.rs".to_owned()),
        )
    };

    let main_rs = format!(
        r##"//! Nyx dynamic harness — UNAUTHORIZED_ID IDOR boundary (Phase 11 / Track J.9).
{mod_decls}use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{{SystemTime, UNIX_EPOCH}};

{shim}

const _NYX_CALLER_ID: &str = "alice";

fn nyx_idor_access_probe(caller: &str, owner: &str) {{
    let p = match env::var("NYX_PROBE_PATH") {{ Ok(s) => s, Err(_) => return }};
    if p.is_empty() {{ return; }}
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let payload_id = env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let mut esc_caller = String::new();
    __nyx_esc(caller, &mut esc_caller);
    let mut esc_owner = String::new();
    __nyx_esc(owner, &mut esc_owner);
    let mut esc_pid = String::new();
    __nyx_esc(&payload_id, &mut esc_pid);
    let mut line = String::with_capacity(256);
    line.push_str("{{\"sink_callee\":\"__nyx_idor_lookup\",\"args\":[");
    line.push_str("{{\"kind\":\"String\",\"value\":\"");
    line.push_str(&esc_caller);
    line.push_str("\"}},{{\"kind\":\"String\",\"value\":\"");
    line.push_str(&esc_owner);
    line.push_str("\"}}],");
    line.push_str("\"captured_at_ns\":");
    line.push_str(&now.to_string());
    line.push_str(",\"payload_id\":\"");
    line.push_str(&esc_pid);
    line.push_str("\",\"kind\":{{\"kind\":\"IdorAccess\",\"caller_id\":\"");
    line.push_str(&esc_caller);
    line.push_str("\",\"owner_id\":\"");
    line.push_str(&esc_owner);
    line.push_str("\"}},\"witness\":");
    line.push_str(&__nyx_witness_json("__nyx_idor_lookup", &[caller, owner]));
    line.push_str("}}\n");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {{
        let _ = f.write_all(line.as_bytes());
    }}
}}

fn main() {{
    __nyx_install_crash_guard("__nyx_idor_lookup");
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
{via_fixture_invoke}    println!("__NYX_SINK_HIT__");
    println!("{{{{\"payload_len\":{{}}}}}}", payload.len());
}}
"##
    );

    HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files,
        entry_subpath,
    }
}

/// Phase 11 (Track J.9) DATA_EXFIL outbound-network harness for Rust.
///
/// Rust has no monkey-patch hook for `reqwest::blocking::get` /
/// `reqwest::get`, but the emitter ships an `nyx_http` module via
/// `extra_files` that exposes the same surface area (`get` /
/// `blocking::get`) and rewrites the fixture's `reqwest::` references
/// to `crate::nyx_http::` so the outbound call routes through a
/// host-capturing shim.  The shim parses the URL host, emits a
/// [`crate::dynamic::probe::ProbeKind::OutboundNetwork`] probe, and
/// returns a benign stand-in `Response` whose `text()` returns an
/// empty string.  No real network egress; no `reqwest` dep is added
/// to `Cargo.toml`, so the harness build avoids the multi-minute
/// reqwest compilation tax.  Falls back to a payload-only path that
/// emits an `OutboundNetwork(payload)` probe when the fixture source
/// is unreachable so the universal sink-hit path still fires.
pub fn emit_data_exfil_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_fn = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let cargo_toml = generate_cargo_toml(Cap::DATA_EXFIL);
    let entry_source = read_entry_source(&spec.entry_file);
    let tier_a_active = !entry_source.is_empty();

    let (mod_decls, via_fixture_invoke, extra_files, entry_subpath) = if tier_a_active {
        let rewritten = rewrite_reqwest_imports(&entry_source);
        let extras: Vec<(String, String)> = vec![
            ("Cargo.toml".into(), cargo_toml),
            ("src/entry.rs".into(), rewritten),
            (
                "src/nyx_http.rs".into(),
                nyx_http_module_source().to_owned(),
            ),
        ];
        let invoke = format!("    let _ = entry::{entry_fn}(&payload);\n",);
        (
            "mod entry;\nmod nyx_http;\n".to_owned(),
            invoke,
            extras,
            Some("ignored/raw_fixture.rs".to_owned()),
        )
    } else {
        let extras: Vec<(String, String)> = vec![("Cargo.toml".into(), cargo_toml)];
        let invoke = "    nyx_outbound_probe(&payload);\n".to_owned();
        (
            String::new(),
            invoke,
            extras,
            Some("ignored/raw_fixture.rs".to_owned()),
        )
    };

    let main_rs = format!(
        r##"//! Nyx dynamic harness — DATA_EXFIL outbound-host (Phase 11 / Track J.9).
{mod_decls}use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{{SystemTime, UNIX_EPOCH}};

{shim}

pub fn nyx_outbound_probe(host: &str) {{
    let p = match env::var("NYX_PROBE_PATH") {{ Ok(s) => s, Err(_) => return }};
    if p.is_empty() {{ return; }}
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let payload_id = env::var("NYX_PAYLOAD_ID").unwrap_or_default();
    let mut esc_host = String::new();
    __nyx_esc(host, &mut esc_host);
    let mut esc_pid = String::new();
    __nyx_esc(&payload_id, &mut esc_pid);
    let mut line = String::with_capacity(256);
    line.push_str("{{\"sink_callee\":\"__nyx_mock_http\",\"args\":[");
    line.push_str("{{\"kind\":\"String\",\"value\":\"");
    line.push_str(&esc_host);
    line.push_str("\"}}],");
    line.push_str("\"captured_at_ns\":");
    line.push_str(&now.to_string());
    line.push_str(",\"payload_id\":\"");
    line.push_str(&esc_pid);
    line.push_str("\",\"kind\":{{\"kind\":\"OutboundNetwork\",\"host\":\"");
    line.push_str(&esc_host);
    line.push_str("\"}},\"witness\":");
    line.push_str(&__nyx_witness_json("__nyx_mock_http", &[host]));
    line.push_str("}}\n");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {{
        let _ = f.write_all(line.as_bytes());
    }}
}}

fn main() {{
    __nyx_install_crash_guard("__nyx_mock_http");
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
{via_fixture_invoke}    println!("__NYX_SINK_HIT__");
    println!("{{{{\"payload_len\":{{}}}}}}", payload.len());
}}
"##
    );

    HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files,
        entry_subpath,
    }
}

/// Rewrite `reqwest::` references in the fixture source to
/// `crate::nyx_http::` so the fixture's outbound call routes through
/// the harness-supplied shim.  Idempotent and byte-level: matches both
/// the `reqwest::blocking::get` form (today's curated Rust DATA_EXFIL
/// fixtures) and the bare `reqwest::get` form (async variant).  A
/// `use reqwest::...;` line is normalised to `use crate::nyx_http::...;`
/// by the same prefix replacement.
fn rewrite_reqwest_imports(src: &str) -> String {
    src.replace("reqwest::", "crate::nyx_http::")
}

/// Source for the `nyx_http` module — permissive stand-in for the
/// fraction of `reqwest::blocking` / `reqwest` the curated Rust
/// DATA_EXFIL fixtures use (`blocking::get(url)` returning a result-
/// shaped value whose `text()` is callable).  The shim parses the URL
/// host, calls [`crate::nyx_outbound_probe`] on the main crate, and
/// returns a benign empty `Response`.  No real wire I/O.
fn nyx_http_module_source() -> &'static str {
    r##"//! Permissive `reqwest` stand-in — record outbound host bytes verbatim.
#![allow(dead_code)]

pub struct Response;

impl Response {
    pub fn text(self) -> Result<String, NyxHttpError> {
        Ok(String::new())
    }

    pub fn bytes(self) -> Result<Vec<u8>, NyxHttpError> {
        Ok(Vec::new())
    }

    pub fn status(&self) -> u16 {
        200
    }
}

#[derive(Debug)]
pub struct NyxHttpError;

impl std::fmt::Display for NyxHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "nyx-http error")
    }
}

impl std::error::Error for NyxHttpError {}

fn extract_host(url: &str) -> String {
    let rest = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let end = rest.find(|c: char| c == '/' || c == '?' || c == '#').unwrap_or(rest.len());
    let authority = &rest[..end];
    match authority.rfind(':') {
        Some(i) => authority[..i].to_owned(),
        None => authority.to_owned(),
    }
}

fn capture<U: AsRef<str>>(url: U) -> Result<Response, NyxHttpError> {
    let host = extract_host(url.as_ref());
    crate::nyx_outbound_probe(&host);
    Ok(Response)
}

/// Top-level `reqwest::get` shape (async stub).  Returns synchronously
/// because the curated fixtures discard the future / response; if a
/// future fixture awaits the value the discard still type-checks.
pub fn get<U: AsRef<str>>(url: U) -> Result<Response, NyxHttpError> {
    capture(url)
}

pub mod blocking {
    use super::{NyxHttpError, Response, capture};

    pub fn get<U: AsRef<str>>(url: U) -> Result<Response, NyxHttpError> {
        capture(url)
    }

    pub struct Client;

    impl Client {
        pub fn new() -> Self {
            Self
        }

        pub fn get<U: AsRef<str>>(&self, url: U) -> RequestBuilder {
            RequestBuilder { url: url.as_ref().to_owned() }
        }
    }

    impl Default for Client {
        fn default() -> Self {
            Self::new()
        }
    }

    pub struct RequestBuilder {
        url: String,
    }

    impl RequestBuilder {
        pub fn send(self) -> Result<Response, NyxHttpError> {
            capture(self.url.as_str())
        }

        pub fn header<K: AsRef<str>, V: AsRef<str>>(self, _key: K, _value: V) -> Self {
            self
        }

        pub fn body<B>(self, _body: B) -> Self {
            self
        }
    }
}
"##
}

/// Emit a Rust harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    // Phase 08 (Track J.6): HEADER_INJECTION-sink short-circuit.  The
    // Rust harness models an `axum`-style `HeaderMap::insert` shim
    // that records the *unmodified* value bytes via a
    // `ProbeKind::HeaderEmit` probe.
    if spec.expected_cap == crate::labels::Cap::HEADER_INJECTION {
        return Ok(emit_header_injection_harness(spec));
    }

    // Phase 09 (Track J.7): OPEN_REDIRECT-sink short-circuit.  The
    // Rust harness models an `axum`-style `Redirect::to(value)` shim
    // that records the bound `Location:` value via a
    // `ProbeKind::Redirect` probe.
    if spec.expected_cap == crate::labels::Cap::OPEN_REDIRECT {
        return Ok(emit_open_redirect_harness(spec));
    }

    // Phase 11 (Track J.9): CRYPTO weak-RNG short-circuit.  Stages the
    // fixture at `src/entry.rs`, builds against `rand = "0.8"` (the
    // benign fixture uses `rand::rngs::OsRng`, the vuln fixture uses
    // `rand::thread_rng().gen_range(...)`), invokes `entry::run(&payload)`,
    // reduces the produced key to a `u64` via the `NyxKeyToInt` trait
    // (`u16`/`u32`/`u64` flow through verbatim, `[u8; N]`/`Vec<u8>`/
    // `String`/`&str` are left-zero-padded to 8 bytes then read as BE
    // u64 so a 32-byte CSPRNG benign result trivially overshoots any
    // 16-bit budget), and writes a `ProbeKind::WeakKey { key_int }`
    // record.
    if spec.expected_cap == crate::labels::Cap::CRYPTO {
        return Ok(emit_crypto_harness(spec));
    }

    // Phase 11 (Track J.9): JSON_PARSE depth-bomb short-circuit.  Stages
    // the fixture at `src/entry.rs`, builds against `serde_json = "1"`,
    // invokes `entry::<entry_name>(&payload)` which is expected to
    // return a `serde_json::Value`, walks that value iteratively, and
    // writes a `ProbeKind::JsonParse { depth, excessive_depth }` record.
    if spec.expected_cap == crate::labels::Cap::JSON_PARSE {
        return Ok(emit_json_parse_harness(spec));
    }

    // Phase 11 (Track J.9): UNAUTHORIZED_ID IDOR short-circuit.  Stages
    // the fixture at `src/entry.rs`, invokes `entry::<entry_name>(&payload)`
    // which is expected to return an `Option<_>`, and emits a
    // `ProbeKind::IdorAccess { caller_id: "alice", owner_id: payload }`
    // record iff the fixture materialised a `Some(_)` record so the
    // benign fixture's `None` boundary-cross rejection clears the
    // predicate.
    if spec.expected_cap == crate::labels::Cap::UNAUTHORIZED_ID {
        return Ok(emit_unauthorized_id_harness(spec));
    }

    // Phase 11 (Track J.9): DATA_EXFIL outbound-network short-circuit.
    // Rust has no monkey-patch hook for `reqwest::blocking::get`, but
    // the emitter ships an `nyx_http` module via `extra_files` and
    // rewrites `reqwest::` references in the fixture source to
    // `crate::nyx_http::` so the fixture's outbound call routes through
    // a host-capturing shim that emits a `ProbeKind::OutboundNetwork`
    // record before returning a benign stand-in `Response`.  No real
    // network egress.
    if spec.expected_cap == crate::labels::Cap::DATA_EXFIL {
        return Ok(emit_data_exfil_harness(spec));
    }

    // Phase 19 (Track M.1): ClassMethod short-circuit.  Rust has no
    // class system — the dispatcher maps `class` to a struct exported
    // from `entry::`, and `method` to a `&self` method on that
    // struct.  The harness constructs the receiver via
    // `<class>::default()` (preferred path), falling back to
    // `<class>::new()` when `Default` is not implemented.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method_harness(spec, class, method));
    }

    // Phase 21 (Track M.3): GraphQLResolver short-circuit (Juniper).
    // Emits a `src/main.rs` that invokes `entry::<handler>(payload)`
    // directly — Juniper resolvers are plain async fns in the source.
    if let crate::evidence::EntryKind::GraphQLResolver { type_name, field } = &spec.entry_kind {
        return Ok(emit_graphql_resolver_harness(spec, type_name, field));
    }

    let shape = detect_shape(spec);

    // Generic + LibfuzzerTarget accept Param(0)/EnvVar; richer shapes
    // (HTTP routes, CLI) additionally route payloads via QueryParam /
    // HttpBody / Argv.  Keep the original restrictive default for the
    // pre-Phase-16 generic path so existing callers don't change shape.
    match (&spec.payload_slot, shape) {
        (PayloadSlot::Param(0) | PayloadSlot::EnvVar(_), _) => {}
        (
            PayloadSlot::QueryParam(_) | PayloadSlot::HttpBody,
            RustShape::ActixWebRoute
            | RustShape::ActixRoute
            | RustShape::AxumHandler
            | RustShape::AxumRoute
            | RustShape::RocketRoute
            | RustShape::WarpRoute,
        ) => {}
        (PayloadSlot::Argv(_), RustShape::ClapCli) => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    let cargo_toml = generate_cargo_toml(spec.expected_cap);
    let main_rs = generate_main_rs(spec, shape);

    Ok(HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files: vec![("Cargo.toml".into(), cargo_toml)],
        entry_subpath: Some("src/entry.rs".into()),
    })
}

/// Phase 19 (Track M.1) — class-method harness for Rust.
///
/// Emits `src/main.rs` that constructs `entry::<class>` and invokes
/// `instance.<method>(&payload)`.  The constructor pick is driven by
/// scanning the entry source for the receiver's construction shape:
/// when the class derives `Default` (or implements `Default` directly)
/// the harness emits `<class>::default()`; otherwise it falls back to
/// `<class>::new()`.  This keeps the harness compilable against
/// non-Default fixtures without a separate emit path.
fn emit_class_method_harness(spec: &HarnessSpec, class: &str, method: &str) -> HarnessSource {
    let shim = probe_shim();
    let cargo_toml = generate_cargo_toml(spec.expected_cap);
    let entry_label = format!("{class}::{method}");
    let entry_src = read_entry_source(&spec.entry_file);
    let receiver_expr = rust_receiver_expr(&entry_src, class, 3);
    let body = format!(
        r#"//! Nyx dynamic harness — class method (Phase 19 / Track M.1).
mod entry;
{shim}
fn main() {{
    let payload = nyx_payload();
    let _ = &payload;
    __nyx_install_crash_guard("{entry_label}");
    let instance = {receiver_expr};
    let _ = instance.{method}(&payload);
    println!("__NYX_SINK_HIT__");
}}

fn nyx_payload() -> String {{
    if let Ok(v) = std::env::var("NYX_PAYLOAD") {{
        if !v.is_empty() {{
            return v;
        }}
    }}
    if let Ok(b64) = std::env::var("NYX_PAYLOAD_B64") {{
        if let Some(bytes) = b64_decode(b64.as_bytes()) {{
            return String::from_utf8_lossy(&bytes).into_owned();
        }}
    }}
    String::new()
}}

fn b64_decode(input: &[u8]) -> Option<Vec<u8>> {{
    const TABLE: [u8; 128] = {{
        let mut t = [255u8; 128];
        let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0usize;
        while i < alphabet.len() {{
            t[alphabet[i] as usize] = i as u8;
            i += 1;
        }}
        t
    }};
    let input: Vec<u8> = input.iter().copied().filter(|&c| c != b'\n' && c != b'\r').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < input.len() {{
        let a = *TABLE.get(input[i] as usize)? as u32;
        let b = *TABLE.get(input[i + 1] as usize)? as u32;
        let c = if input[i + 2] == b'=' {{ 64 }} else {{ *TABLE.get(input[i + 2] as usize)? as u32 }};
        let d = if input[i + 3] == b'=' {{ 64 }} else {{ *TABLE.get(input[i + 3] as usize)? as u32 }};
        if a == 255 || b == 255 || c == 255 || d == 255 {{ return None; }}
        out.push(((a << 2) | (b >> 4)) as u8);
        if input[i + 2] != b'=' {{ out.push(((b << 4) | (c >> 2)) as u8); }}
        if input[i + 3] != b'=' {{ out.push(((c << 6) | d) as u8); }}
        i += 4;
    }}
    Some(out)
}}
"#,
        method = method,
        entry_label = entry_label,
        receiver_expr = receiver_expr,
    );
    HarnessSource {
        source: body,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files: vec![("Cargo.toml".into(), cargo_toml)],
        entry_subpath: Some("src/entry.rs".into()),
    }
}

fn rust_receiver_expr(entry_src: &str, class: &str, depth: usize) -> String {
    if class_derives_default(entry_src, class) {
        return format!("entry::{class}::default()");
    }
    if class_has_new(entry_src, class) {
        return format!("entry::{class}::new()");
    }
    rust_struct_literal(entry_src, class, depth).unwrap_or_else(|| format!("entry::{class}::new()"))
}

fn class_has_new(entry_src: &str, class: &str) -> bool {
    let impl_marker = format!("impl {class}");
    let Some(mut pos) = entry_src.find(&impl_marker) else {
        return false;
    };
    loop {
        let after = &entry_src[pos + impl_marker.len()..];
        if let Some(open_rel) = after.find('{') {
            let body = &after[open_rel + 1..];
            if let Some(close_rel) = body.find("\n}")
                && word_in_text(&body[..close_rel], "new")
                && body[..close_rel].contains("fn new")
            {
                return true;
            }
        }
        let next_from = pos + impl_marker.len();
        let Some(next_rel) = entry_src[next_from..].find(&impl_marker) else {
            return false;
        };
        pos = next_from + next_rel;
    }
}

fn rust_struct_literal(entry_src: &str, class: &str, depth: usize) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let fields = rust_struct_fields(entry_src, class)?;
    let mut parts = Vec::new();
    for (name, ty) in fields {
        parts.push(format!(
            "{name}: {}",
            rust_value_for_type(entry_src, &ty, depth - 1)
        ));
    }
    Some(format!("entry::{class} {{ {} }}", parts.join(", ")))
}

fn rust_struct_fields(entry_src: &str, class: &str) -> Option<Vec<(String, String)>> {
    let marker = format!("struct {class}");
    let idx = entry_src.find(&marker)?;
    let after = &entry_src[idx + marker.len()..];
    let open = after.find('{')?;
    let body = balanced_block(&after[open..])?;
    let inner = &body[1..body.len() - 1];
    let mut out = Vec::new();
    for part in split_top_level_commas(inner) {
        let mut text = part.trim();
        if text.is_empty() {
            continue;
        }
        while text.starts_with("#[") {
            let end = text.find(']')?;
            text = text[end + 1..].trim_start();
        }
        let text = text.strip_prefix("pub ").unwrap_or(text).trim_start();
        let colon = text.find(':')?;
        let name = text[..colon].trim();
        let ty = text[colon + 1..].trim();
        if !name.is_empty() && !ty.is_empty() {
            out.push((name.to_owned(), ty.to_owned()));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn balanced_block(text: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&text[..=idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0isize;
    let mut start = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' | ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&text[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

fn rust_value_for_type(entry_src: &str, ty: &str, depth: usize) -> String {
    let clean = ty.trim().trim_start_matches('&').trim();
    let bare = clean
        .split('<')
        .next()
        .unwrap_or(clean)
        .rsplit("::")
        .next()
        .unwrap_or(clean)
        .trim();
    match bare {
        "String" => "String::new()".to_owned(),
        "str" => "\"\"".to_owned(),
        "bool" => "false".to_owned(),
        "char" => "'\\0'".to_owned(),
        "usize" | "u8" | "u16" | "u32" | "u64" | "u128" | "isize" | "i8" | "i16" | "i32"
        | "i64" | "i128" => "0".to_owned(),
        "f32" | "f64" => "0.0".to_owned(),
        _ if clean.starts_with("Option<") => "None".to_owned(),
        _ if clean.starts_with("Vec<") => "Vec::new()".to_owned(),
        _ if clean.starts_with("Box<") && clean.ends_with('>') => {
            let inner = &clean["Box<".len()..clean.len() - 1];
            format!("Box::new({})", rust_value_for_type(entry_src, inner, depth))
        }
        _ if depth > 0 && rust_struct_fields(entry_src, bare).is_some() => {
            rust_receiver_expr(entry_src, bare, depth)
        }
        _ => "Default::default()".to_owned(),
    }
}

// ── Phase 21 (Track M.3) — synthetic entry-kind harnesses ─────────────────────

/// Phase 21 (Track M.3) — GraphQL resolver harness for Rust (Juniper).
///
/// Emits a `src/main.rs` that invokes `entry::<handler>(&payload)` —
/// the harness assumes the entry module exposes a free function with
/// the resolver name; Juniper's `#[graphql_object]` impl methods are
/// not directly reachable through `mod entry`, so the v1 path goes
/// through a thin re-export the entry file is expected to publish.
fn emit_graphql_resolver_harness(
    spec: &HarnessSpec,
    type_name: &str,
    field: &str,
) -> HarnessSource {
    let shim = probe_shim();
    let cargo_toml = generate_cargo_toml(spec.expected_cap);
    let handler = &spec.entry_name;
    let label = format!("{type_name}.{field}");
    let body = format!(
        r#"//! Nyx dynamic harness — GraphQL resolver (Phase 21 / Track M.3).
mod entry;
{shim}
fn main() {{
    let payload = nyx_payload();
    __nyx_install_crash_guard("{label}");
    println!("__NYX_GRAPHQL_RESOLVER__: {type_name}.{field}");
    println!("__NYX_SINK_HIT__");
    let _ = entry::{handler}(&payload);
}}

fn nyx_payload() -> String {{
    if let Ok(v) = std::env::var("NYX_PAYLOAD") {{
        if !v.is_empty() {{
            return v;
        }}
    }}
    if let Ok(b64) = std::env::var("NYX_PAYLOAD_B64") {{
        if let Some(bytes) = b64_decode(b64.as_bytes()) {{
            return String::from_utf8_lossy(&bytes).into_owned();
        }}
    }}
    String::new()
}}

fn b64_decode(input: &[u8]) -> Option<Vec<u8>> {{
    const TABLE: [u8; 128] = {{
        let mut t = [255u8; 128];
        let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0usize;
        while i < alphabet.len() {{
            t[alphabet[i] as usize] = i as u8;
            i += 1;
        }}
        t
    }};
    let input: Vec<u8> = input.iter().copied().filter(|&c| c != b'\n' && c != b'\r').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < input.len() {{
        let a = *TABLE.get(input[i] as usize)? as u32;
        let b = *TABLE.get(input[i + 1] as usize)? as u32;
        let c = if input[i + 2] == b'=' {{ 64 }} else {{ *TABLE.get(input[i + 2] as usize)? as u32 }};
        let d = if input[i + 3] == b'=' {{ 64 }} else {{ *TABLE.get(input[i + 3] as usize)? as u32 }};
        if a == 255 || b == 255 || c == 255 || d == 255 {{ return None; }}
        out.push(((a << 2) | (b >> 4)) as u8);
        if input[i + 2] != b'=' {{ out.push(((b << 4) | (c >> 2)) as u8); }}
        if input[i + 3] != b'=' {{ out.push(((c << 6) | d) as u8); }}
        i += 4;
    }}
    Some(out)
}}
"#,
        handler = handler,
        type_name = type_name,
        field = field,
        label = label,
    );
    HarnessSource {
        source: body,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files: vec![("Cargo.toml".into(), cargo_toml)],
        entry_subpath: Some("src/entry.rs".into()),
    }
}

/// True when the entry source declares `class` as a type that derives
/// or implements `Default`.  Two byte-level patterns are recognised:
///
/// - `#[derive(...Default...)]` immediately preceding a `struct`/`enum`
///   declaration whose name matches `class`.
/// - An explicit `impl Default for <class>` block anywhere in the file.
///
/// When neither is present the caller falls back to a `<class>::new()`
/// ctor.  The scan is conservative: unrecognised entry sources produce
/// `false` (so the harness emits `new()`), which keeps non-Default
/// fixtures compilable.
fn class_derives_default(entry_src: &str, class: &str) -> bool {
    let impl_marker = format!("impl Default for {class}");
    if entry_src.contains(&impl_marker) {
        return true;
    }
    let struct_marker = format!("struct {class}");
    let enum_marker = format!("enum {class}");
    let mut search_from = 0usize;
    let bytes = entry_src.as_bytes();
    loop {
        let struct_at = entry_src[search_from..].find(&struct_marker);
        let enum_at = entry_src[search_from..].find(&enum_marker);
        let (rel, marker_len) = match (struct_at, enum_at) {
            (Some(s), Some(e)) if s <= e => (s, struct_marker.len()),
            (Some(_), Some(e)) => (e, enum_marker.len()),
            (Some(s), None) => (s, struct_marker.len()),
            (None, Some(e)) => (e, enum_marker.len()),
            (None, None) => return false,
        };
        let decl_pos = search_from + rel;
        let next_byte = bytes.get(decl_pos + marker_len).copied();
        let boundary_ok = matches!(next_byte, Some(b) if !b.is_ascii_alphanumeric() && b != b'_');
        if boundary_ok {
            let window_start = decl_pos.saturating_sub(256);
            let window = &entry_src[window_start..decl_pos];
            if let Some(derive_pos) = window.rfind("#[derive(")
                && let Some(end_rel) = window[derive_pos..].find(")]")
            {
                let end = derive_pos + end_rel;
                let derive_list = &window[derive_pos + "#[derive(".len()..end];
                let between = &window[end + ")]".len()..];
                // The derive attribute must directly precede the
                // declaration — no other item / statement may sit
                // between `#[derive(...)]` and the `struct` /
                // `enum` token.  Forbidden tokens (`;`, `{`, `}`,
                // `=`, or another item keyword) signal the derive
                // belongs to an earlier declaration.
                let between_clean = strip_attrs_and_comments(between);
                let forbidden = ['{', '}', ';', '='];
                let item_keyword = ["struct", "enum", "fn", "impl", "trait", "type", "mod"]
                    .iter()
                    .any(|kw| word_in_text(&between_clean, kw));
                let attaches_to_decl =
                    !between_clean.chars().any(|c| forbidden.contains(&c)) && !item_keyword;
                if attaches_to_decl && derive_list.split(',').any(|t| t.trim() == "Default") {
                    return true;
                }
            }
        }
        search_from = decl_pos + 1;
    }
}

/// Drop `//` line comments and `#[...]` attribute blocks from `text`,
/// returning the remaining bytes joined by spaces.  Used by
/// [`class_derives_default`] to decide whether the text between a
/// derive attribute and a declaration is empty (modulo visibility
/// modifiers and other attributes).
fn strip_attrs_and_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let mut s = line.trim();
        while s.starts_with("#[") {
            if let Some(end) = s.find(']') {
                s = s[end + 1..].trim_start();
            } else {
                break;
            }
        }
        if let Some(idx) = s.find("//") {
            s = &s[..idx];
        }
        out.push_str(s.trim());
        out.push(' ');
    }
    out
}

/// True when `kw` appears in `text` as a whole word (ASCII word
/// boundaries on both sides).
fn word_in_text(text: &str, kw: &str) -> bool {
    let bytes = text.as_bytes();
    let kw_bytes = kw.as_bytes();
    if kw_bytes.is_empty() {
        return false;
    }
    let mut i = 0usize;
    while i + kw_bytes.len() <= bytes.len() {
        if &bytes[i..i + kw_bytes.len()] == kw_bytes {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_';
            let after_idx = i + kw_bytes.len();
            let after_ok = after_idx >= bytes.len()
                || (!bytes[after_idx].is_ascii_alphanumeric() && bytes[after_idx] != b'_');
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Generate `Cargo.toml` for the harness crate.
///
/// Dependencies are driven by `expected_cap`:
/// - `SQL_QUERY` → `rusqlite` with the `bundled` feature (embeds SQLite).
/// - Other caps use only std (no extra deps).
///
/// `libc` is always pinned because the Phase 16 probe shim (spliced into
/// `src/main.rs` by [`generate_main_rs`]) calls `libc::sigaction` from
/// `__nyx_install_crash_guard`.  The shim is unconditionally compiled so
/// the dep must be unconditional too.
pub fn generate_cargo_toml(cap: Cap) -> String {
    generate_cargo_toml_with_extras(cap, false)
}

/// Variant of [`generate_cargo_toml`] that conditionally pulls in
/// `percent-encoding` for the HEADER_INJECTION benign control fixture
/// (it routes the value through `utf8_percent_encode` to land CRLF as
/// `%0D%0A`).  No extra dep weight for tier-(b) builds.
pub fn generate_cargo_toml_with_extras(cap: Cap, needs_percent_encoding: bool) -> String {
    let mut deps = String::new();

    deps.push_str("libc = \"0.2\"\n");
    if cap.contains(Cap::SQL_QUERY) {
        deps.push_str("rusqlite = { version = \"0.39\", features = [\"bundled\"] }\n");
    }
    if needs_percent_encoding {
        deps.push_str("percent-encoding = \"2\"\n");
    }
    if cap.contains(Cap::CRYPTO) {
        deps.push_str("rand = \"0.8\"\n");
    }
    if cap.contains(Cap::JSON_PARSE) {
        deps.push_str("serde_json = \"1\"\n");
    }

    format!(
        "[package]\n\
         name = \"nyx-harness\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n\n\
         [[bin]]\n\
         name = \"nyx_harness\"\n\
         path = \"src/main.rs\"\n\n\
         [dependencies]\n\
         {deps}"
    )
}

/// Generate `src/main.rs` — the harness entry point.
///
/// Reads the payload from env, calls `entry::{entry_name}` with the payload
/// routed according to `spec.payload_slot` and `shape`.  The probe shim
/// (Phase 06 / Phase 08) is spliced in at file scope so
/// `__nyx_install_crash_guard` is callable from `main` before the entry
/// invocation.
fn generate_main_rs(spec: &HarnessSpec, shape: RustShape) -> String {
    let entry_fn = &spec.entry_name;
    let (pre_call, call_expr) = build_call(spec, entry_fn, shape);
    let shim = probe_shim();
    let entry_label = spec.entry_name.replace('\\', "\\\\").replace('"', "\\\"");

    format!(
        r#"//! Nyx dynamic harness — auto-generated, do not edit (Phase 16 — RustShape::{shape:?}).
mod entry;
{shim}
fn main() {{
    let payload = nyx_payload();
    let _ = &payload;
    // Phase 08 sink-site signal handler: install AFTER payload decode so a
    // crash in `nyx_payload` / `b64_decode` (harness setup) writes no Crash
    // probe.  A crash inside the entry call below fires the handler and
    // writes a Crash probe to NYX_PROBE_PATH for `Oracle::SinkCrash`.
    __nyx_install_crash_guard("{entry_label}");
{pre_call}    {call_expr}
}}

fn nyx_payload() -> String {{
    // Prefer raw NYX_PAYLOAD (set on Unix).
    if let Ok(v) = std::env::var("NYX_PAYLOAD") {{
        if !v.is_empty() {{
            return v;
        }}
    }}
    // Fall back to base64-encoded NYX_PAYLOAD_B64.
    if let Ok(b64) = std::env::var("NYX_PAYLOAD_B64") {{
        if let Some(bytes) = b64_decode(b64.as_bytes()) {{
            return String::from_utf8_lossy(&bytes).into_owned();
        }}
    }}
    String::new()
}}

/// Minimal base64 decoder (no external deps).
fn b64_decode(input: &[u8]) -> Option<Vec<u8>> {{
    const TABLE: [u8; 128] = {{
        // `while` loop (not `for`) so the initializer stays inside what stable
        // Rust permits in a `const` context: `IntoIterator::into_iter` is not a
        // const fn, so a `for` loop here fails with E0015.
        let mut t = [255u8; 128];
        let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0usize;
        while i < alphabet.len() {{
            t[alphabet[i] as usize] = i as u8;
            i += 1;
        }}
        t
    }};
    let input: Vec<u8> = input.iter().copied().filter(|&c| c != b'\n' && c != b'\r').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < input.len() {{
        let a = *TABLE.get(input[i] as usize)? as u32;
        let b = *TABLE.get(input[i + 1] as usize)? as u32;
        let c = if input[i + 2] == b'=' {{ 64 }} else {{ *TABLE.get(input[i + 2] as usize)? as u32 }};
        let d = if input[i + 3] == b'=' {{ 64 }} else {{ *TABLE.get(input[i + 3] as usize)? as u32 }};
        if a == 255 || b == 255 || c == 255 || d == 255 {{ return None; }}
        out.push(((a << 2) | (b >> 4)) as u8);
        if input[i + 2] != b'=' {{ out.push(((b << 4) | (c >> 2)) as u8); }}
        if input[i + 3] != b'=' {{ out.push(((c << 6) | d) as u8); }}
        i += 4;
    }}
    Some(out)
}}
"#,
        shape = shape,
        pre_call = pre_call,
        call_expr = call_expr,
    )
}

/// Build `(pre_call_setup, call_expression)` strings for the chosen payload
/// slot and per-shape invocation pattern.
fn build_call(spec: &HarnessSpec, func: &str, shape: RustShape) -> (String, String) {
    match shape {
        RustShape::Generic => match &spec.payload_slot {
            PayloadSlot::Param(0) => (String::new(), format!("entry::{func}(&payload);")),
            PayloadSlot::EnvVar(name) => (
                format!("    std::env::set_var({name:?}, &payload);\n"),
                format!("entry::{func}();"),
            ),
            _ => (String::new(), format!("entry::{func}(&payload);")),
        },
        RustShape::LibfuzzerTarget => {
            // libfuzzer targets take `&[u8]`.
            (String::new(), format!("entry::{func}(payload.as_bytes());"))
        }
        RustShape::ActixWebRoute => actix_invocation(spec, func),
        RustShape::AxumHandler => axum_invocation(spec, func),
        // Phase 17 framework dispatchers.  Each shape prints the
        // matching toolchain marker before invoking the entry under
        // the same reflective shim used by [`Self::ActixWebRoute`] /
        // [`Self::AxumHandler`].  Real-framework bootstrap (full
        // `Router` mount, `App::new`, `rocket::build`, `warp::serve`)
        // is deferred behind the per-shape harness real-engine
        // follow-up — see `.pitboss/play/deferred.md`.
        RustShape::ActixRoute => framework_route_invocation(spec, func, "NYX_ACTIX_TEST=1"),
        RustShape::AxumRoute => framework_route_invocation(spec, func, "NYX_AXUM_TEST=1"),
        RustShape::RocketRoute => framework_route_invocation(spec, func, "NYX_ROCKET_TEST=1"),
        RustShape::WarpRoute => framework_route_invocation(spec, func, "NYX_WARP_TEST=1"),
        RustShape::ClapCli => clap_invocation(spec, func),
    }
}

fn framework_route_invocation(spec: &HarnessSpec, func: &str, marker: &str) -> (String, String) {
    let pre = format!("    println!(\"{marker}\");\n");
    let (inner_pre, call) = actix_invocation(spec, func);
    (format!("{pre}{inner_pre}"), call)
}

fn actix_invocation(spec: &HarnessSpec, func: &str) -> (String, String) {
    // Real actix_web requires an async runtime; the test fixtures use a
    // synchronous shim signature `pub fn <func>(payload: &str) -> String`
    // to keep build deps zero. The harness driver invokes it directly.
    match &spec.payload_slot {
        PayloadSlot::Param(0) => (String::new(), format!("let _ = entry::{func}(&payload);")),
        PayloadSlot::EnvVar(name) => (
            format!("    std::env::set_var({name:?}, &payload);\n"),
            format!("let _ = entry::{func}(\"\");"),
        ),
        PayloadSlot::HttpBody => (String::new(), format!("let _ = entry::{func}(&payload);")),
        PayloadSlot::QueryParam(name) => (
            String::new(),
            format!("let _ = entry::{func}(&format!(\"{name}={{}}\", payload));",),
        ),
        _ => (String::new(), format!("let _ = entry::{func}(&payload);")),
    }
}

fn axum_invocation(spec: &HarnessSpec, func: &str) -> (String, String) {
    actix_invocation(spec, func)
}

fn clap_invocation(spec: &HarnessSpec, func: &str) -> (String, String) {
    // Emulate clap's args by passing the payload as the sole positional
    // argument. Fixture entry signature: `pub fn <func>(args: Vec<String>)`.
    let pad = match &spec.payload_slot {
        PayloadSlot::Argv(n) => *n,
        _ => 0,
    };
    let mut pre = String::from("    let mut argv = vec![\"nyx_harness\".to_string()];\n");
    for _ in 0..pad {
        pre.push_str("    argv.push(String::new());\n");
    }
    pre.push_str("    argv.push(payload.clone());\n");
    let call = format!("entry::{func}(argv);");
    (pre, call)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "rust000000000001".into(),
            entry_file: "src/handler.rs".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Rust,
            toolchain_id: "rust-stable".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/handler.rs".into(),
            sink_line: 10,
            spec_hash: "rusttest00000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn emit_sql_query_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("mod entry;"));
        assert!(harness.source.contains("nyx_payload()"));
        assert!(harness.source.contains("entry::run(&payload)"));
        assert_eq!(harness.filename, "src/main.rs");
        assert_eq!(harness.command, vec!["target/release/nyx_harness"]);
    }

    #[test]
    fn emit_includes_cargo_toml_in_extra_files() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        let cargo = harness.extra_files.iter().find(|(n, _)| n == "Cargo.toml");
        assert!(cargo.is_some(), "Cargo.toml must be in extra_files");
        let cargo_content = &cargo.unwrap().1;
        assert!(
            cargo_content.contains("rusqlite"),
            "SQL_QUERY cap needs rusqlite dep"
        );
        assert!(
            cargo_content.contains("bundled"),
            "rusqlite must use bundled feature"
        );
    }

    #[test]
    fn emit_code_exec_no_rusqlite_dep() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::CODE_EXEC;
        let harness = emit(&spec).unwrap();
        let cargo = harness
            .extra_files
            .iter()
            .find(|(n, _)| n == "Cargo.toml")
            .unwrap();
        assert!(
            !cargo.1.contains("rusqlite"),
            "CODE_EXEC must not have rusqlite dep"
        );
    }

    #[test]
    fn emit_entry_subpath_is_src_entry_rs() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("src/entry.rs".to_string()));
    }

    #[test]
    fn class_derives_default_matches_derive_attribute() {
        let src = "#[derive(Default)]\npub struct UserService;";
        assert!(class_derives_default(src, "UserService"));
    }

    #[test]
    fn class_derives_default_matches_derive_among_other_traits() {
        let src = "#[derive(Clone, Debug, Default, PartialEq)]\nstruct UserService { id: u32 }";
        assert!(class_derives_default(src, "UserService"));
    }

    #[test]
    fn class_derives_default_matches_explicit_impl() {
        let src =
            "struct UserService;\nimpl Default for UserService { fn default() -> Self { Self } }";
        assert!(class_derives_default(src, "UserService"));
    }

    #[test]
    fn class_derives_default_matches_enum() {
        let src = "#[derive(Default)]\nenum Mode { #[default] Off, On }";
        assert!(class_derives_default(src, "Mode"));
    }

    #[test]
    fn class_derives_default_false_when_absent() {
        let src = "pub struct UserService { id: u32 }\nimpl UserService { pub fn new() -> Self { Self { id: 0 } } }";
        assert!(!class_derives_default(src, "UserService"));
    }

    #[test]
    fn class_derives_default_false_when_derive_on_different_type() {
        let src = "#[derive(Default)]\nstruct OtherType;\npub struct UserService;";
        assert!(!class_derives_default(src, "UserService"));
    }

    #[test]
    fn class_derives_default_respects_word_boundary() {
        // `struct UserServiceImpl` must not be treated as `UserService`.
        let src = "#[derive(Default)]\nstruct UserServiceImpl;";
        assert!(!class_derives_default(src, "UserService"));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("NYX_INPUT".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("set_var"));
        assert!(harness.source.contains("\"NYX_INPUT\""));
    }

    #[test]
    fn emit_param_gt_0_is_unsupported() {
        let spec = make_spec(PayloadSlot::Param(1));
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
    }

    #[test]
    fn cargo_toml_has_correct_bin_target() {
        let cargo = generate_cargo_toml(Cap::SQL_QUERY);
        assert!(cargo.contains("name = \"nyx_harness\""));
        assert!(cargo.contains("path = \"src/main.rs\""));
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!RustEmitter.entry_kinds_supported().is_empty());
        assert!(
            RustEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::Function)
        );
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = RustEmitter.entry_kind_hint(EntryKindTag::LibraryApi);
        assert!(hint.contains("LibraryApi"));
        assert!(hint.contains("Phase 16"));
    }

    // ── Phase 16: shape detection ────────────────────────────────────────────

    fn make_spec_with(kind: EntryKind, name: &str, entry_file: &str) -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.entry_kind = kind;
        s.entry_name = name.to_owned();
        s.entry_file = entry_file.to_owned();
        s
    }

    #[test]
    fn shape_detect_axum_handler() {
        // Phase 17 — Track L.15: a strong `use axum::` import now
        // routes to the framework-aware [`RustShape::AxumRoute`]
        // shape; the legacy [`RustShape::AxumHandler`] fires only on
        // weak detectors (`IntoResponse` / `Json(` without `use
        // axum::`).
        let src =
            "use axum::extract::Query; pub fn handler(payload: &str) -> String { String::new() }";
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::AxumRoute);
    }

    #[test]
    fn shape_detect_axum_weak_falls_back_to_axum_handler() {
        // No `use axum::` / `axum::Router` and no `axum::` token in
        // the body — the weak detector (`IntoResponse` / bare `Json(`)
        // routes to the legacy [`RustShape::AxumHandler`] shape.
        let src = "pub fn handler() -> impl IntoResponse { let _ = Json(\"\".to_string()); }";
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::AxumHandler);
    }

    #[test]
    fn shape_detect_actix_route() {
        // Phase 17 — Track L.15: a strong `use actix_web::` import
        // + attribute macro `#[get(...)]` routes to the
        // [`RustShape::ActixRoute`] shape.  Plain `use actix_web::`
        // without an attribute macro still uses the legacy
        // [`RustShape::ActixWebRoute`].
        let src = "use actix_web::HttpResponse; pub fn handler(payload: &str) -> String { String::new() }";
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::ActixWebRoute);
    }

    #[test]
    fn shape_detect_actix_attribute_route() {
        let src = "use actix_web::get;\n#[get(\"/x\")]\npub async fn handler() -> String { String::new() }";
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::ActixRoute);
    }

    #[test]
    fn shape_detect_rocket_route() {
        let src = "use rocket::get;\n#[get(\"/x\")]\nfn handler() -> &'static str { \"ok\" }";
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::RocketRoute);
    }

    #[test]
    fn shape_detect_warp_route() {
        let src = "use warp::Filter;\nfn build() { let r = warp::path!(\"x\").map(handler); }";
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::WarpRoute);
    }

    #[test]
    fn shape_detect_clap_cli() {
        let src = "use clap::Parser; pub fn run(args: Vec<String>) {}";
        let spec = make_spec_with(EntryKind::CliSubcommand, "run", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::ClapCli);
    }

    #[test]
    fn shape_detect_libfuzzer_target() {
        let src = "pub fn fuzz_target(data: &[u8]) {}";
        let spec = make_spec_with(EntryKind::LibraryApi, "fuzz_target", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::LibfuzzerTarget);
    }

    #[test]
    fn shape_detect_generic_fallback() {
        let src = "pub fn run(payload: &str) {}";
        let spec = make_spec_with(EntryKind::Function, "run", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::Generic);
    }

    #[test]
    fn axum_shape_emits_str_invocation() {
        let mut spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        spec.payload_slot = PayloadSlot::QueryParam("q".into());
        let src = generate_main_rs(&spec, RustShape::AxumHandler);
        assert!(src.contains("entry::handler"));
        assert!(src.contains("q={}"));
    }

    #[test]
    fn axum_shape_param0_passes_raw_payload() {
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        let src = generate_main_rs(&spec, RustShape::AxumHandler);
        assert!(src.contains("entry::handler(&payload)"));
    }

    #[test]
    fn clap_shape_emits_argv() {
        let mut spec = make_spec_with(EntryKind::CliSubcommand, "run", "src/entry.rs");
        spec.payload_slot = PayloadSlot::Argv(0);
        let src = generate_main_rs(&spec, RustShape::ClapCli);
        assert!(src.contains("argv.push(payload.clone())"));
        assert!(src.contains("entry::run(argv)"));
    }

    #[test]
    fn libfuzzer_shape_emits_bytes_invocation() {
        let spec = make_spec_with(EntryKind::LibraryApi, "fuzz_target", "src/entry.rs");
        let src = generate_main_rs(&spec, RustShape::LibfuzzerTarget);
        assert!(src.contains("entry::fuzz_target(payload.as_bytes())"));
    }

    #[test]
    fn axum_route_emits_marker() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "src/entry.rs");
        let src = generate_main_rs(&spec, RustShape::AxumRoute);
        assert!(
            src.contains("NYX_AXUM_TEST=1"),
            "AxumRoute must print NYX_AXUM_TEST=1 marker, got: {src}",
        );
    }

    #[test]
    fn actix_route_emits_marker() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "src/entry.rs");
        let src = generate_main_rs(&spec, RustShape::ActixRoute);
        assert!(src.contains("NYX_ACTIX_TEST=1"));
    }

    #[test]
    fn rocket_route_emits_marker() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "src/entry.rs");
        let src = generate_main_rs(&spec, RustShape::RocketRoute);
        assert!(src.contains("NYX_ROCKET_TEST=1"));
    }

    #[test]
    fn warp_route_emits_marker() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "src/entry.rs");
        let src = generate_main_rs(&spec, RustShape::WarpRoute);
        assert!(src.contains("NYX_WARP_TEST=1"));
    }

    #[test]
    fn emit_splices_probe_shim_and_installs_crash_guard() {
        // Phase 16 follow-up: Rust emitter now splices probe_shim() into
        // src/main.rs and installs the sink-site signal handler around the
        // entry call.  Mirrors the C / C++ splicing tests.
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        assert!(
            h.source.contains("__nyx_probe shim (Phase 06 — Track C.1"),
            "probe_shim banner missing from generated src/main.rs",
        );
        assert!(
            h.source.contains("fn __nyx_install_crash_guard("),
            "install_crash_guard definition missing from generated src/main.rs",
        );
        assert!(
            h.source.contains("__nyx_install_crash_guard(\"run\");"),
            "install_crash_guard call site missing or wrong callee",
        );
        let install_pos = h
            .source
            .find("__nyx_install_crash_guard(\"run\");")
            .unwrap();
        let payload_pos = h.source.find("let payload = nyx_payload();").unwrap();
        let invoke_pos = h.source.find("entry::run(&payload);").unwrap();
        assert!(
            payload_pos < install_pos && install_pos < invoke_pos,
            "install_crash_guard ordering wrong: payload={payload_pos} install={install_pos} invoke={invoke_pos}",
        );
    }

    #[test]
    fn cargo_toml_always_pins_libc_for_probe_shim() {
        // Phase 16 follow-up: the probe shim calls `libc::sigaction` so
        // `libc` must be unconditionally pinned (independent of the
        // expected_cap dep matrix).
        for cap in [Cap::SQL_QUERY, Cap::CODE_EXEC, Cap::FILE_IO, Cap::SSRF] {
            let cargo = generate_cargo_toml(cap);
            assert!(
                cargo.contains("libc = \"0.2\""),
                "libc dep missing for cap={cap:?}",
            );
        }
    }

    #[test]
    fn b64_decode_roundtrip() {
        // Test by compiling: actual b64_decode is in generated code.
        // Just verify the Cargo.toml generation doesn't panic.
        let _ = generate_cargo_toml(Cap::FILE_IO);
        let _ = generate_cargo_toml(Cap::CODE_EXEC);
        let _ = generate_cargo_toml(Cap::SSRF);
    }

    #[test]
    fn chain_step_splices_probe_shim_for_composite_reverify() {
        // Phase 26 follow-up: Rust chain_step now splices the probe
        // shim ahead of the driver so a chain step that terminates at
        // a sink can drive the `__nyx_probe` channel directly.  The
        // shim references `libc::*` so the step also ships a companion
        // `Cargo.toml` via `extra_files` and drives the build through
        // `cargo run --quiet` rather than single-file `rustc`.
        let step = chain_step(Some(b"prev-output"), None);
        assert!(
            step.source.contains("__nyx_probe shim (Phase 06"),
            "probe_shim banner missing from chain step source",
        );
        assert!(
            step.source.contains("fn __nyx_install_crash_guard("),
            "install_crash_guard missing from chain step source",
        );
        let shim_pos = step
            .source
            .find("__nyx_probe shim (Phase 06")
            .expect("shim banner");
        let main_pos = step.source.find("fn main()").expect("main fn");
        assert!(
            shim_pos < main_pos,
            "shim must be spliced before fn main(): shim={shim_pos} main={main_pos}",
        );
        assert_eq!(step.filename, "step.rs");
        assert_eq!(
            step.command,
            vec!["cargo".to_owned(), "run".to_owned(), "--quiet".to_owned()],
        );
        assert!(
            step.extra_env
                .iter()
                .any(|(k, v)| k == ChainStepHarness::PREV_OUTPUT_ENV && v == "prev-output"),
            "prev_output must be threaded through extra_env, got {:?}",
            step.extra_env,
        );
    }

    #[test]
    fn probe_shim_publishes_stub_recorders() {
        // Phase 10 (Track D.3): the Rust probe shim ships the SQL +
        // HTTP recording helpers alongside the existing crash-guard /
        // probe-emit machinery so a sink callsite can surface
        // attempted boundary calls when the on-the-wire stub never
        // sees them.  Asserts the helper names + the `NYX_*_LOG` env
        // hooks are present so future raw-string-delimiter regressions
        // (`r#"..."#` → `r##"..."##`) get caught early.
        let shim = probe_shim();
        assert!(
            shim.contains("fn __nyx_stub_sql_record("),
            "Rust probe shim must define __nyx_stub_sql_record",
        );
        assert!(
            shim.contains("fn __nyx_stub_http_record("),
            "Rust probe shim must define __nyx_stub_http_record",
        );
        assert!(
            shim.contains("NYX_SQL_LOG"),
            "SQL recorder must read NYX_SQL_LOG",
        );
        assert!(
            shim.contains("NYX_HTTP_LOG"),
            "HTTP recorder must read NYX_HTTP_LOG",
        );
    }

    // ── Phase 08 / 09 tier-(a) helpers + emitters ───────────────────────────

    #[test]
    fn rewrite_axum_imports_replaces_header_map_path() {
        let src = "use axum::http::HeaderMap;\nuse axum::http::HeaderValue;\npub fn run() {}";
        let out = rewrite_axum_imports(src);
        assert!(
            out.contains("crate::nyx_harness_stubs::HeaderMap"),
            "HeaderMap import must rewrite to local stub: {out}",
        );
        assert!(
            out.contains("crate::nyx_harness_stubs::HeaderValue"),
            "HeaderValue import must rewrite to local stub: {out}",
        );
        assert!(
            !out.contains("axum::http::HeaderMap"),
            "raw axum::http::HeaderMap must be gone: {out}",
        );
    }

    #[test]
    fn rewrite_axum_imports_replaces_redirect_path() {
        let src = "use axum::response::Redirect;\npub fn run() {}";
        let out = rewrite_axum_imports(src);
        assert!(
            out.contains("crate::nyx_harness_stubs::Redirect"),
            "Redirect import must rewrite to local stub: {out}",
        );
        assert!(
            !out.contains("axum::response::Redirect"),
            "raw axum::response::Redirect must be gone: {out}",
        );
    }

    #[test]
    fn rewrite_axum_imports_passes_through_when_unmatched() {
        let src = "use std::fs;\npub fn run() {}\n";
        assert_eq!(rewrite_axum_imports(src), src);
    }

    #[test]
    fn entry_source_imports_axum_header_matches_qualified_form() {
        assert!(entry_source_imports_axum_header(
            "use axum::http::HeaderMap;"
        ));
        assert!(entry_source_imports_axum_header(
            "let h: http::HeaderMap = HeaderMap::new();"
        ));
        assert!(!entry_source_imports_axum_header(
            "use std::collections::HashMap;"
        ));
    }

    #[test]
    fn entry_source_imports_axum_redirect_matches_qualified_form() {
        assert!(entry_source_imports_axum_redirect(
            "use axum::response::Redirect;"
        ));
        assert!(entry_source_imports_axum_redirect(
            "fn x() -> response::Redirect { todo!() }"
        ));
        assert!(!entry_source_imports_axum_redirect("use std::fs;"));
    }

    #[test]
    fn rust_header_stubs_source_exposes_required_surface() {
        let src = rust_header_stubs_source();
        assert!(src.contains("pub struct HeaderValue"));
        assert!(src.contains("pub struct HeaderMap"));
        assert!(src.contains("pub struct Redirect"));
        assert!(src.contains("pub fn from_bytes"));
        assert!(src.contains("pub fn from_str"));
        assert!(src.contains("pub fn insert<K"));
        assert!(src.contains("pub fn iter("));
        assert!(src.contains("pub fn to(s: &str) -> Self"));
        assert!(src.contains("pub fn location("));
    }

    #[test]
    fn header_injection_tier_a_fires_when_axum_imported() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = "tests/dynamic_fixtures/header_injection/rust/vuln.rs".into();
        let harness = emit_header_injection_harness(&spec);
        assert!(
            harness.source.contains("mod entry;"),
            "tier-(a) header_injection main.rs must declare mod entry",
        );
        assert!(
            harness.source.contains("mod nyx_harness_stubs;"),
            "tier-(a) header_injection main.rs must declare mod nyx_harness_stubs",
        );
        assert!(
            harness.source.contains("nyx_header_via_fixture(&payload)"),
            "tier-(a) header_injection must dispatch via fixture wrapper",
        );
        assert!(
            harness.source.contains("entry::run(&mut headers, payload)"),
            "tier-(a) header_injection must invoke entry::run with headers + payload",
        );
        // Rewritten fixture staged under src/entry.rs.
        let staged = harness
            .extra_files
            .iter()
            .find(|(p, _)| p == "src/entry.rs");
        assert!(
            staged.is_some(),
            "tier-(a) header_injection must stage src/entry.rs",
        );
        assert!(
            staged
                .unwrap()
                .1
                .contains("crate::nyx_harness_stubs::HeaderMap"),
            "staged fixture must have axum imports rewritten",
        );
        // Stub module staged.
        let stub = harness
            .extra_files
            .iter()
            .find(|(p, _)| p == "src/nyx_harness_stubs.rs");
        assert!(stub.is_some(), "tier-(a) must stage nyx_harness_stubs.rs");
        // Raw fixture parked outside src/ so cargo ignores it.
        assert_eq!(
            harness.entry_subpath.as_deref(),
            Some("ignored/raw_fixture.rs"),
        );
    }

    #[test]
    fn header_injection_tier_b_falls_back_when_no_axum() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = "/nonexistent/missing.rs".into();
        let harness = emit_header_injection_harness(&spec);
        assert!(
            !harness.source.contains("mod entry;"),
            "tier-(b) header_injection must not declare mod entry",
        );
        assert!(
            harness
                .source
                .contains("nyx_header_probe(\"Set-Cookie\", &payload)"),
            "tier-(b) header_injection must emit synthetic Set-Cookie probe",
        );
        assert!(
            harness
                .extra_files
                .iter()
                .all(|(p, _)| p != "src/entry.rs" && p != "src/nyx_harness_stubs.rs"),
            "tier-(b) header_injection must not stage rewritten fixture or stubs",
        );
        assert_eq!(harness.entry_subpath.as_deref(), Some("src/entry.rs"));
    }

    #[test]
    fn header_injection_routes_through_wire_frame_when_raw_socket_imported() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = "tests/dynamic_fixtures/header_injection/rust_raw/vuln.rs".into();
        let harness = emit_header_injection_harness(&spec);
        assert!(
            harness.source.contains("mod entry;"),
            "wire-frame harness must declare mod entry: {body}",
            body = harness.source,
        );
        assert!(
            !harness.source.contains("mod nyx_harness_stubs;"),
            "wire-frame harness must not pull the axum stubs: {body}",
            body = harness.source,
        );
        assert!(
            harness
                .source
                .contains("fn nyx_wire_frame_via_fixture(payload: &str)"),
            "wire-frame harness must declare the fixture-driving helper: {body}",
            body = harness.source,
        );
        assert!(
            harness
                .source
                .contains("entry::set_cookie_value(payload.as_bytes())"),
            "wire-frame harness must install cookie value on the fixture: {body}",
            body = harness.source,
        );
        assert!(
            harness
                .source
                .contains("std::panic::catch_unwind(entry::create_server)"),
            "wire-frame harness must guard fixture TcpListener boot failures: {body}",
            body = harness.source,
        );
        assert!(
            harness
                .source
                .contains("return Some(nyx_fallback_wire_frame(payload))"),
            "wire-frame harness must fall back to deterministic raw headers when loopback I/O is denied: {body}",
            body = harness.source,
        );
        assert!(
            harness
                .source
                .contains("fn nyx_fallback_wire_frame(payload: &str) -> Vec<u8>"),
            "wire-frame harness must define the deterministic fallback wire frame: {body}",
            body = harness.source,
        );
        assert!(
            harness
                .source
                .contains("thread::spawn(move || entry::run_once(listener))"),
            "wire-frame harness must drive the fixture's run_once on a worker thread: {body}",
            body = harness.source,
        );
        assert!(
            harness
                .source
                .contains(".write_all(b\"GET / HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n\")"),
            "wire-frame harness must issue raw GET request: {body}",
            body = harness.source,
        );
        assert!(
            harness
                .source
                .contains(r#"HeaderWireFrame\",\"raw_bytes\":"#),
            "wire-frame harness must emit a HeaderWireFrame probe carrying the raw header-block bytes: {body}",
            body = harness.source,
        );
        assert!(
            harness.source.contains(r#"\"protocol\":\"wire\""#),
            "wire-frame harness must tag derived HeaderEmit records as wire protocol: {body}",
            body = harness.source,
        );
        assert!(
            harness.source.contains("wire_frame_len"),
            "wire-frame harness must emit the wire_frame_len stdout marker: {body}",
            body = harness.source,
        );
        assert_eq!(harness.entry_subpath.as_deref(), Some("src/entry.rs"));
        // Cargo.toml must still be staged so the workdir builds.
        assert!(
            harness.extra_files.iter().any(|(p, _)| p == "Cargo.toml"),
            "wire-frame harness must stage Cargo.toml: {files:?}",
            files = harness
                .extra_files
                .iter()
                .map(|(p, _)| p.clone())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn header_injection_wire_frame_branch_drops_when_only_axum_imported() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = "tests/dynamic_fixtures/header_injection/rust/vuln.rs".into();
        let harness = emit_header_injection_harness(&spec);
        assert!(
            !harness
                .source
                .contains("fn nyx_wire_frame_via_fixture(payload: &str)"),
            "axum harness must not pull the wire-frame helper: {body}",
            body = harness.source,
        );
        assert!(
            !harness.source.contains("HeaderWireFrame"),
            "axum harness must not emit the HeaderWireFrame probe shape: {body}",
            body = harness.source,
        );
        assert!(
            !harness.source.contains("wire_frame_len"),
            "axum harness must not print the wire-frame stdout marker: {body}",
            body = harness.source,
        );
    }

    #[test]
    fn header_injection_tier_a_pulls_percent_encoding_when_benign_uses_it() {
        // Benign fixture imports `percent_encoding`; tier-(a) must pin
        // the dep so the workdir build resolves the symbol.
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = "tests/dynamic_fixtures/header_injection/rust/benign.rs".into();
        let harness = emit_header_injection_harness(&spec);
        let cargo = harness
            .extra_files
            .iter()
            .find(|(p, _)| p == "Cargo.toml")
            .expect("Cargo.toml staged");
        assert!(
            cargo.1.contains("percent-encoding = \"2\""),
            "benign fixture's percent_encoding import must pin the dep, got: {body}",
            body = cargo.1,
        );
    }

    #[test]
    fn open_redirect_tier_a_fires_when_axum_imported() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = "tests/dynamic_fixtures/open_redirect/rust/vuln.rs".into();
        let harness = emit_open_redirect_harness(&spec);
        assert!(
            harness.source.contains("mod entry;"),
            "tier-(a) open_redirect main.rs must declare mod entry",
        );
        assert!(
            harness.source.contains("mod nyx_harness_stubs;"),
            "tier-(a) open_redirect main.rs must declare mod nyx_harness_stubs",
        );
        assert!(
            harness
                .source
                .contains("nyx_redirect_via_fixture(payload.clone())"),
            "tier-(a) open_redirect must dispatch via fixture wrapper",
        );
        assert!(
            harness.source.contains("entry::run(payload)"),
            "tier-(a) open_redirect must invoke entry::run with payload",
        );
        let staged = harness
            .extra_files
            .iter()
            .find(|(p, _)| p == "src/entry.rs");
        assert!(
            staged.is_some(),
            "tier-(a) open_redirect must stage src/entry.rs"
        );
        assert!(
            staged
                .unwrap()
                .1
                .contains("crate::nyx_harness_stubs::Redirect"),
            "staged fixture must have axum::response::Redirect rewritten",
        );
        let stub = harness
            .extra_files
            .iter()
            .find(|(p, _)| p == "src/nyx_harness_stubs.rs");
        assert!(
            stub.is_some(),
            "tier-(a) open_redirect must stage nyx_harness_stubs.rs"
        );
        assert_eq!(
            harness.entry_subpath.as_deref(),
            Some("ignored/raw_fixture.rs"),
        );
    }

    #[test]
    fn open_redirect_tier_b_falls_back_when_no_axum() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = "/nonexistent/missing.rs".into();
        let harness = emit_open_redirect_harness(&spec);
        assert!(
            !harness.source.contains("mod entry;"),
            "tier-(b) open_redirect must not declare mod entry",
        );
        assert!(
            harness
                .source
                .contains("nyx_redirect_probe(&location, request_host)"),
            "tier-(b) open_redirect must emit synthetic redirect probe",
        );
        assert!(
            harness
                .extra_files
                .iter()
                .all(|(p, _)| p != "src/entry.rs" && p != "src/nyx_harness_stubs.rs"),
            "tier-(b) open_redirect must not stage rewritten fixture or stubs",
        );
    }

    #[test]
    fn emit_open_redirect_harness_ships_follow_location_helper() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = "/nonexistent/missing.rs".into();
        let harness = emit_open_redirect_harness(&spec);
        assert!(
            harness
                .source
                .contains("fn nyx_follow_location(location: &str)"),
            "OPEN_REDIRECT harness must declare the nyx_follow_location helper",
        );
        for prefix in [
            "http://127.0.0.1",
            "http://localhost",
            "http://host-gateway",
        ] {
            assert!(
                harness
                    .source
                    .contains(&format!("starts_with(\"{prefix}\")")),
                "follower must gate on loopback {prefix} prefix",
            );
        }
        assert!(
            harness.source.contains("TcpStream::connect_timeout"),
            "follower must drive a zero-dep TcpStream::connect_timeout against the captured Location",
        );
        assert!(
            harness.source.contains("GET {path} HTTP/1.0"),
            "follower must write a HTTP/1.0 GET request line",
        );
        // Tier-(b) callsite must call the follower on the synthetic payload.
        assert!(
            harness.source.contains(
                "nyx_redirect_probe(&location, request_host);\n    nyx_follow_location(&location);"
            ),
            "tier-(b) callsite must invoke nyx_follow_location after the synthetic probe",
        );
    }

    #[test]
    fn emit_open_redirect_harness_follows_captured_location_in_tier_a() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "run".into();
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = "tests/dynamic_fixtures/open_redirect/rust/vuln.rs".into();
        let harness = emit_open_redirect_harness(&spec);
        // Tier-(a) callsite: captured loc → probe + follow.
        assert!(
            harness.source.contains(
                "nyx_redirect_probe(&location, request_host);\n    nyx_follow_location(&location);"
            ),
            "tier-(a) callsite must invoke nyx_follow_location on the captured Location",
        );
    }

    #[test]
    fn cargo_toml_extras_pins_percent_encoding_when_requested() {
        let cargo = generate_cargo_toml_with_extras(Cap::HEADER_INJECTION, true);
        assert!(cargo.contains("libc = \"0.2\""));
        assert!(cargo.contains("percent-encoding = \"2\""));
        let cargo_no_extras = generate_cargo_toml_with_extras(Cap::HEADER_INJECTION, false);
        assert!(cargo_no_extras.contains("libc = \"0.2\""));
        assert!(!cargo_no_extras.contains("percent-encoding"));
    }

    #[test]
    fn chain_step_emits_cargo_toml_with_libc_dep() {
        let step = chain_step(None, None);
        let cargo = step
            .extra_files
            .iter()
            .find(|(n, _)| n == "Cargo.toml")
            .expect("Cargo.toml must be in extra_files for cargo run");
        let body = &cargo.1;
        assert!(
            body.contains("libc = \"0.2\""),
            "Cargo.toml must pin libc for the probe shim's sigaction path, got: {body}",
        );
        assert!(
            body.contains("path = \"step.rs\""),
            "[[bin]] must point at step.rs so cargo run picks it up, got: {body}",
        );
        assert!(
            body.contains("edition = \"2021\""),
            "Cargo.toml must declare edition 2021, got: {body}",
        );
    }

    // ── Phase 11 (Track J.9) Rust CRYPTO emitter tests ─────────────────────────

    fn make_crypto_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::CRYPTO;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_crypto_harness_when_cap_is_crypto() {
        let h = emit(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/rust/vuln.rs",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("fn nyx_weak_key_probe"),
            "dispatcher must short-circuit Cap::CRYPTO into emit_crypto_harness so the weak-key probe shim is present: {}",
            h.source
        );
        // The harness source quotes the JSON field names with escaped
        // backslashes (the generated Rust code splices the JSON via
        // `push_str("\"kind\":\"WeakKey\"")`).  Assert against the
        // escaped form so the test pins the runtime probe shape, not
        // an accidental colocation.
        assert!(
            h.source.contains(r#"\"kind\":\"WeakKey\""#),
            "Rust CRYPTO harness must record probes with kind WeakKey so the WeakKeyEntropy predicate fires: {}",
            h.source
        );
    }

    #[test]
    fn emit_crypto_harness_invokes_entry_via_mod_entry() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/rust/vuln.rs",
            "run",
        ));
        assert!(
            h.source.contains("mod entry;"),
            "Rust CRYPTO harness must declare `mod entry;` so the staged fixture is in scope: {}",
            h.source
        );
        assert!(
            h.source.contains("let produced = entry::run(&payload);"),
            "Rust CRYPTO harness must invoke the entry function with the payload: {}",
            h.source
        );
        assert_eq!(
            h.entry_subpath,
            Some("src/entry.rs".to_string()),
            "Rust CRYPTO harness must stage the fixture at src/entry.rs so `mod entry;` picks it up",
        );
        assert_eq!(
            h.filename, "src/main.rs",
            "Rust CRYPTO harness main file must be src/main.rs",
        );
    }

    #[test]
    fn emit_crypto_harness_emits_weak_key_probe_kind() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/rust/vuln.rs",
            "run",
        ));
        assert!(
            h.source
                .contains(r#"\"kind\":{\"kind\":\"WeakKey\",\"key_int\":"#),
            "Rust CRYPTO harness must emit ProbeKind::WeakKey records carrying a key_int field so the WeakKeyEntropy predicate fires: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_SINK_HIT__"),
            "Rust CRYPTO harness must print the universal sink-hit sentinel: {}",
            h.source
        );
    }

    #[test]
    fn emit_crypto_harness_cargo_toml_pulls_in_rand_crate() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/rust/vuln.rs",
            "run",
        ));
        let cargo = h
            .extra_files
            .iter()
            .find(|(n, _)| n == "Cargo.toml")
            .expect("Cargo.toml must be in extra_files");
        assert!(
            cargo.1.contains("rand = \"0.8\""),
            "Rust CRYPTO harness Cargo.toml must depend on rand = \"0.8\" so the fixture's `rand::thread_rng()` / `rand::rngs::OsRng` imports resolve: {}",
            cargo.1
        );
        assert!(
            cargo.1.contains("libc = \"0.2\""),
            "Rust CRYPTO harness Cargo.toml must keep libc dep for the probe shim's sigaction path",
        );
    }

    #[test]
    fn emit_crypto_harness_reduces_byte_array_via_be_u64() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/rust/benign.rs",
            "run",
        ));
        assert!(
            h.source.contains("fn nyx_bytes_to_key_int"),
            "Rust CRYPTO harness must define the byte-slice reduction helper: {}",
            h.source
        );
        assert!(
            h.source.contains("u64::from_be_bytes"),
            "Rust CRYPTO harness must use big-endian u64 reduction so a 32-byte CSPRNG benign result overshoots any 16-bit budget: {}",
            h.source
        );
        assert!(
            h.source
                .contains("impl<const N: usize> NyxKeyToInt for [u8; N]"),
            "Rust CRYPTO harness must provide a generic [u8; N] impl so both [u8; 32] (benign) and other-sized array returns reduce uniformly: {}",
            h.source
        );
    }

    #[test]
    fn emit_crypto_harness_provides_impls_for_primitive_int_returns() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/rust/vuln.rs",
            "run",
        ));
        for ty in &["u8", "u16", "u32", "u64", "i64", "bool"] {
            let needle = format!("impl NyxKeyToInt for {ty}");
            assert!(
                h.source.contains(&needle),
                "Rust CRYPTO harness must provide a NyxKeyToInt impl for {ty} so fixture return-type variation does not break compilation: {}",
                h.source
            );
        }
    }

    #[test]
    fn emit_crypto_harness_signed_impls_mask_sign_bit() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/rust/vuln.rs",
            "run",
        ));
        assert!(
            h.source.contains("(self as u64) & (i64::MAX as u64)"),
            "signed-int impls must mask the sign bit so a negative key value does not flip a small-bit-budget predicate: {}",
            h.source
        );
    }

    #[test]
    fn emit_crypto_harness_honours_entry_name_when_set() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/rust/vuln.rs",
            "weak_key_derivation",
        ));
        assert!(
            h.source.contains("entry::weak_key_derivation(&payload)"),
            "Rust CRYPTO harness must use spec.entry_name (not a hard-coded literal) when invoking the entry: {}",
            h.source
        );
    }

    // ── Phase 11 (Track J.9) Rust JSON_PARSE emitter tests ─────────────────────

    fn make_json_parse_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::JSON_PARSE;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_json_parse_harness_when_cap_is_json_parse() {
        let h = emit(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/rust/vuln.rs",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("fn nyx_json_parse_probe"),
            "dispatcher must short-circuit Cap::JSON_PARSE into emit_json_parse_harness so the depth probe shim is present: {}",
            h.source
        );
        assert!(
            h.source.contains(r#"\"kind\":\"JsonParse\""#),
            "Rust JSON_PARSE harness must record probes with kind JsonParse: {}",
            h.source
        );
    }

    #[test]
    fn emit_json_parse_harness_invokes_entry_via_mod_entry() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/rust/vuln.rs",
            "run",
        ));
        assert!(
            h.source.contains("mod entry;"),
            "Rust JSON_PARSE harness must declare `mod entry;` so the staged fixture is in scope",
        );
        assert!(
            h.source.contains("let parsed = entry::run(&payload);"),
            "Rust JSON_PARSE harness must invoke the entry function with the payload",
        );
        assert_eq!(h.entry_subpath, Some("src/entry.rs".to_string()));
        assert_eq!(h.filename, "src/main.rs");
    }

    #[test]
    fn emit_json_parse_harness_cargo_toml_pulls_in_serde_json() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/rust/vuln.rs",
            "run",
        ));
        let cargo = h
            .extra_files
            .iter()
            .find(|(n, _)| n == "Cargo.toml")
            .expect("Cargo.toml must be in extra_files");
        assert!(
            cargo.1.contains("serde_json = \"1\""),
            "Rust JSON_PARSE harness Cargo.toml must depend on serde_json so the fixture's parser resolves: {}",
            cargo.1
        );
        assert!(
            cargo.1.contains("libc = \"0.2\""),
            "Rust JSON_PARSE harness Cargo.toml must keep libc dep for the probe shim's sigaction path",
        );
    }

    #[test]
    fn emit_json_parse_harness_uses_iterative_walker() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/rust/vuln.rs",
            "run",
        ));
        assert!(
            h.source.contains("fn nyx_json_count_depth"),
            "Rust JSON_PARSE harness must define the iterative depth walker: {}",
            h.source
        );
        assert!(
            h.source.contains("serde_json::Value::Array(items)"),
            "depth walker must dispatch on serde_json::Value::Array",
        );
        assert!(
            h.source.contains("serde_json::Value::Object(map)"),
            "depth walker must dispatch on serde_json::Value::Object",
        );
    }

    #[test]
    fn emit_json_parse_harness_emits_depth_fields() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/rust/vuln.rs",
            "run",
        ));
        assert!(h.source.contains(r#"\"depth\":"#));
        assert!(h.source.contains(r#"\"excessive_depth\":"#));
        assert!(h.source.contains("depth > 64"));
        assert!(h.source.contains("__NYX_SINK_HIT__"));
    }

    // ── Phase 11 (Track J.9) Rust UNAUTHORIZED_ID emitter tests ────────────────

    fn make_unauthorized_id_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::UNAUTHORIZED_ID;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_unauthorized_id_harness_when_cap_is_unauthorized_id() {
        let h = emit(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/rust/vuln.rs",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyx_idor_access_probe"),
            "dispatcher must short-circuit Cap::UNAUTHORIZED_ID into emit_unauthorized_id_harness so the IDOR probe shim is present",
        );
        assert!(
            h.source.contains(r#"\"kind\":\"IdorAccess\""#),
            "Rust UNAUTHORIZED_ID harness must record probes with kind IdorAccess so IdorBoundaryCrossed fires",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_pins_caller_id() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/rust/vuln.rs",
            "run",
        ));
        assert!(
            h.source.contains("const _NYX_CALLER_ID: &str = \"alice\";"),
            "Rust UNAUTHORIZED_ID harness must pin caller_id to \"alice\"",
        );
        assert!(
            h.source
                .contains("nyx_idor_access_probe(_NYX_CALLER_ID, &payload)"),
            "Rust UNAUTHORIZED_ID harness must call probe with caller_id + payload-as-owner",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_gates_probe_on_some_record() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/rust/benign.rs",
            "run",
        ));
        assert!(
            h.source.contains("let nyx_record = entry::run(&payload);"),
            "Rust UNAUTHORIZED_ID harness must invoke the fixture entry and bind its return",
        );
        assert!(
            h.source.contains("if nyx_record.is_some() {"),
            "Rust UNAUTHORIZED_ID harness must gate probe emission on Some so the benign fixture's None boundary-cross rejection clears the predicate",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_stages_entry_via_extra_files() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/rust/vuln.rs",
            "run",
        ));
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "src/entry.rs");
        assert!(
            staged.is_some(),
            "tier-(a) UNAUTHORIZED_ID harness must stage the fixture at src/entry.rs so `mod entry;` resolves",
        );
        let body = &staged.unwrap().1;
        assert!(
            body.contains("pub fn run(owner_id: &str)"),
            "staged entry.rs must carry the fixture's `run` signature verbatim",
        );
        assert!(
            h.source.contains("mod entry;"),
            "main.rs must declare `mod entry;` so the staged file is reachable",
        );
        assert_eq!(
            h.entry_subpath,
            Some("ignored/raw_fixture.rs".to_owned()),
            "entry_subpath must park the runner's raw copy out of the way so the staged tier-(a) copy wins",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_falls_back_when_fixture_source_unavailable() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::UNAUTHORIZED_ID;
        spec.entry_file = "/nonexistent/path/missing.rs".into();
        spec.entry_name = "run".into();
        let h = emit_unauthorized_id_harness(&spec);
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "src/entry.rs");
        assert!(
            staged.is_none(),
            "fallback path must not stage an entry copy when the fixture cannot be read",
        );
        assert!(
            !h.source.contains("mod entry;"),
            "fallback path must omit `mod entry;` so the harness compiles without src/entry.rs",
        );
        assert!(
            h.source
                .contains("nyx_idor_access_probe(_NYX_CALLER_ID, &payload)"),
            "fallback path must still emit an IDOR probe so the universal sink-hit path fires",
        );
    }

    // ── Phase 11 (Track J.9) Rust DATA_EXFIL emitter tests ─────────────────────

    fn make_data_exfil_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::DATA_EXFIL;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_data_exfil_harness_when_cap_is_data_exfil() {
        let h = emit(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/rust/vuln.rs",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyx_outbound_probe"),
            "dispatcher must short-circuit Cap::DATA_EXFIL into emit_data_exfil_harness so the outbound probe shim is present",
        );
        assert!(
            h.source.contains(r#"\"kind\":\"OutboundNetwork\""#),
            "Rust DATA_EXFIL harness must record probes with kind OutboundNetwork so OutboundHostNotIn fires",
        );
    }

    #[test]
    fn emit_data_exfil_harness_ships_nyx_http_shim() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/rust/vuln.rs",
            "run",
        ));
        let shim = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "src/nyx_http.rs");
        assert!(
            shim.is_some(),
            "Rust DATA_EXFIL harness must ship the nyx_http shim so the rewritten fixture compiles without a real reqwest dep",
        );
        let body = &shim.unwrap().1;
        assert!(
            body.contains("pub mod blocking"),
            "nyx_http shim must expose the `blocking` submodule the fixture's reqwest::blocking path rewrites to",
        );
        assert!(
            body.contains("crate::nyx_outbound_probe"),
            "nyx_http shim must call back into the harness's nyx_outbound_probe so the captured host is emitted",
        );
        assert!(
            h.source.contains("mod nyx_http;"),
            "main.rs must declare `mod nyx_http;` so the shim resolves at crate-root",
        );
    }

    #[test]
    fn emit_data_exfil_harness_rewrites_reqwest_imports_in_staged_entry() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/rust/vuln.rs",
            "run",
        ));
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "src/entry.rs");
        assert!(
            staged.is_some(),
            "tier-(a) DATA_EXFIL harness must stage the rewritten fixture at src/entry.rs",
        );
        let body = &staged.unwrap().1;
        assert!(
            !body.contains("reqwest::blocking"),
            "staged entry.rs must have `reqwest::` references rewritten away so the harness does not pull the real reqwest dep",
        );
        assert!(
            body.contains("crate::nyx_http::blocking"),
            "staged entry.rs must route reqwest::blocking calls through crate::nyx_http::blocking",
        );
    }

    #[test]
    fn rewrite_reqwest_imports_is_idempotent_and_byte_level() {
        let src = "use reqwest::blocking::Client;\nlet _ = reqwest::blocking::get(&url);\nlet _ = reqwest::get(&u).await;";
        let once = rewrite_reqwest_imports(src);
        assert!(once.contains("crate::nyx_http::blocking::Client"));
        assert!(once.contains("crate::nyx_http::blocking::get(&url)"));
        assert!(once.contains("crate::nyx_http::get(&u)"));
        let twice = rewrite_reqwest_imports(&once);
        assert_eq!(once, twice, "rewrite must be idempotent");
    }

    #[test]
    fn emit_data_exfil_harness_invokes_fixture_entry() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/rust/vuln.rs",
            "run",
        ));
        assert!(
            h.source.contains("let _ = entry::run(&payload);"),
            "Rust DATA_EXFIL harness must invoke entry::run via the rewritten fixture so reqwest calls land in the shim",
        );
    }

    #[test]
    fn emit_data_exfil_harness_falls_back_when_fixture_source_unavailable() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::DATA_EXFIL;
        spec.entry_file = "/nonexistent/path/missing.rs".into();
        spec.entry_name = "run".into();
        let h = emit_data_exfil_harness(&spec);
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "src/nyx_http.rs");
        assert!(
            staged.is_none(),
            "fallback path must not stage the nyx_http shim when the fixture cannot be read",
        );
        assert!(
            !h.source.contains("mod entry;"),
            "fallback path must omit `mod entry;` so the harness compiles without src/entry.rs",
        );
        assert!(
            h.source.contains("nyx_outbound_probe(&payload)"),
            "fallback path must still emit an outbound probe so the universal sink-hit path fires",
        );
    }
}
