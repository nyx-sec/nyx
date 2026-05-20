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
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented
/// `headers_mut().insert("Set-Cookie", value)` shim that records the
/// *unmodified* value bytes (including any embedded `\r\n`) via a
/// `ProbeKind::HeaderEmit` probe.  Std-only — no `Cargo.toml`
/// dependencies beyond the always-pinned `libc` (used by the probe
/// shim's crash guard).
pub fn emit_header_injection_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let cargo_toml = generate_cargo_toml(Cap::HEADER_INJECTION);
    let main_rs = format!(
        r##"//! Nyx dynamic harness — HEADER_INJECTION HeaderMap::insert (Phase 08 / Track J.6).
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{{SystemTime, UNIX_EPOCH}};

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
    line.push_str("\"}},\"witness\":{{}}}}\n");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {{
        let _ = f.write_all(line.as_bytes());
    }}
}}

fn main() {{
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
    let name = "Set-Cookie";
    let value = &payload;
    nyx_header_probe(name, value);
    println!("__NYX_SINK_HIT__");
    let mut body = String::new();
    body.push_str("{{\"name\":\"");
    body.push_str(&nyx_json_escape(name));
    body.push_str("\",\"value\":\"");
    body.push_str(&nyx_json_escape(value));
    body.push_str("\"}}");
    println!("{{body}}", body = body);
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

/// Phase 09 — Track J.7 open-redirect harness for Rust
/// (`axum::response::Redirect::to`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented
/// `Redirect::to(value)` shim that records the bound `Location:`
/// value plus the request's origin host via a `ProbeKind::Redirect`
/// probe.  Std-only — no `Cargo.toml` dependencies beyond the
/// always-pinned `libc`.
pub fn emit_open_redirect_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let cargo_toml = generate_cargo_toml(Cap::OPEN_REDIRECT);
    let main_rs = format!(
        r##"//! Nyx dynamic harness — OPEN_REDIRECT Redirect::to (Phase 09 / Track J.7).
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{{SystemTime, UNIX_EPOCH}};

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

fn main() {{
    let payload = env::var("NYX_PAYLOAD").unwrap_or_default();
    let request_host = "example.com";
    let location = &payload;
    nyx_redirect_probe(location, request_host);
    println!("__NYX_SINK_HIT__");
    let mut body = String::new();
    body.push_str("{{\"location\":\"");
    body.push_str(&nyx_json_escape(location));
    body.push_str("\",\"request_host\":\"");
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
        extra_files: vec![("Cargo.toml".into(), cargo_toml)],
        entry_subpath: Some("src/entry.rs".into()),
    }
}

fn read_entry_source(entry_file: &str) -> String {
    let candidates = [PathBuf::from(entry_file), PathBuf::from(".").join(entry_file)];
    for path in &candidates {
        if let Ok(s) = std::fs::read_to_string(path) {
            return s;
        }
    }
    String::new()
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

    // Phase 19 (Track M.1): ClassMethod short-circuit.  Rust has no
    // class system — the dispatcher maps `class` to a struct exported
    // from `entry::`, and `method` to a `&self` method on that
    // struct.  The harness constructs the receiver via
    // `<class>::default()` (preferred path), falling back to
    // `<class>::new()` when `Default` is not implemented.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method_harness(spec, class, method));
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
    let ctor = if class_derives_default(&entry_src, class) {
        "default"
    } else {
        "new"
    };
    let body = format!(
        r#"//! Nyx dynamic harness — class method (Phase 19 / Track M.1).
mod entry;
{shim}
fn main() {{
    let payload = nyx_payload();
    let _ = &payload;
    __nyx_install_crash_guard("{entry_label}");
    let instance = entry::{class}::{ctor}();
    let _ = instance.{method}(&payload);
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
        class = class,
        method = method,
        entry_label = entry_label,
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
            if let Some(derive_pos) = window.rfind("#[derive(") {
                if let Some(end_rel) = window[derive_pos..].find(")]") {
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
                    let attaches_to_decl = !between_clean.chars().any(|c| forbidden.contains(&c))
                        && !item_keyword;
                    if attaches_to_decl
                        && derive_list.split(',').any(|t| t.trim() == "Default")
                    {
                        return true;
                    }
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
            let before_ok = i == 0
                || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_';
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
    let mut deps = String::new();

    deps.push_str("libc = \"0.2\"\n");
    if cap.contains(Cap::SQL_QUERY) {
        deps.push_str("rusqlite = { version = \"0.39\", features = [\"bundled\"] }\n");
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
        PayloadSlot::HttpBody => (
            String::new(),
            format!("let _ = entry::{func}(&payload);"),
        ),
        PayloadSlot::QueryParam(name) => (
            String::new(),
            format!(
                "let _ = entry::{func}(&format!(\"{name}={{}}\", payload));",
            ),
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
        assert!(cargo_content.contains("rusqlite"), "SQL_QUERY cap needs rusqlite dep");
        assert!(cargo_content.contains("bundled"), "rusqlite must use bundled feature");
    }

    #[test]
    fn emit_code_exec_no_rusqlite_dep() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::CODE_EXEC;
        let harness = emit(&spec).unwrap();
        let cargo = harness.extra_files.iter().find(|(n, _)| n == "Cargo.toml").unwrap();
        assert!(!cargo.1.contains("rusqlite"), "CODE_EXEC must not have rusqlite dep");
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
        let src = "struct UserService;\nimpl Default for UserService { fn default() -> Self { Self } }";
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
        assert!(RustEmitter
            .entry_kinds_supported()
            .contains(&EntryKindTag::Function));
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
        let src = "use axum::extract::Query; pub fn handler(payload: &str) -> String { String::new() }";
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
}
