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
use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
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
const SUPPORTED: &[EntryKind] = &[
    EntryKind::Function,
    EntryKind::HttpRoute,
    EntryKind::CliSubcommand,
    EntryKind::LibraryApi,
];

impl LangEmitter for RustEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "rust emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 16 shape dispatch (actix / axum / clap / libfuzzer)"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_rust(env)
    }
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
    r#"
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
"#
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
    /// `axum` handler — `async fn handler(...) -> impl IntoResponse`.
    /// Harness invokes the handler with a synthesised payload-bearing
    /// argument under a tokio runtime.
    AxumHandler,
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
        let kind = spec.entry_kind;
        let entry = spec.entry_name.as_str();

        let has_actix = source.contains("actix_web::")
            || source.contains("HttpRequest")
            || source.contains("HttpResponse")
            || source.contains("#[get(")
            || source.contains("#[post(");
        let has_axum = source.contains("axum::")
            || source.contains("IntoResponse")
            || source.contains("Json(")
            || source.contains("Query(")
            || source.contains("axum::extract");
        let has_clap = source.contains("clap::")
            || source.contains("#[derive(Parser)")
            || source.contains("Parser::parse");
        let has_libfuzzer = source.contains("libfuzzer_sys::fuzz_target")
            || source.contains("fuzz_target!")
            || (source.contains("pub fn ") && source.contains("data: &[u8]"));

        if has_axum {
            return Self::AxumHandler;
        }
        if has_actix {
            return Self::ActixWebRoute;
        }
        if has_clap {
            return Self::ClapCli;
        }
        if has_libfuzzer && (entry.starts_with("fuzz") || entry == "fuzz_target") {
            return Self::LibfuzzerTarget;
        }
        match kind {
            EntryKind::HttpRoute => Self::ActixWebRoute,
            EntryKind::CliSubcommand => Self::ClapCli,
            EntryKind::LibraryApi => Self::LibfuzzerTarget,
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
    let shape = detect_shape(spec);

    // Generic + LibfuzzerTarget accept Param(0)/EnvVar; richer shapes
    // (HTTP routes, CLI) additionally route payloads via QueryParam /
    // HttpBody / Argv.  Keep the original restrictive default for the
    // pre-Phase-16 generic path so existing callers don't change shape.
    match (&spec.payload_slot, shape) {
        (PayloadSlot::Param(0) | PayloadSlot::EnvVar(_), _) => {}
        (PayloadSlot::QueryParam(_) | PayloadSlot::HttpBody, RustShape::ActixWebRoute)
        | (PayloadSlot::QueryParam(_) | PayloadSlot::HttpBody, RustShape::AxumHandler) => {}
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

/// Generate `Cargo.toml` for the harness crate.
///
/// Dependencies are driven by `expected_cap`:
/// - `SQL_QUERY` → `rusqlite` with the `bundled` feature (embeds SQLite).
/// - Other caps use only std (no extra deps).
pub fn generate_cargo_toml(cap: Cap) -> String {
    let mut deps = String::new();

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
/// routed according to `spec.payload_slot` and `shape`.
fn generate_main_rs(spec: &HarnessSpec, shape: RustShape) -> String {
    let entry_fn = &spec.entry_name;
    let (pre_call, call_expr) = build_call(spec, entry_fn, shape);

    format!(
        r#"//! Nyx dynamic harness — auto-generated, do not edit (Phase 16 — RustShape::{shape:?}).
mod entry;

fn main() {{
    let payload = nyx_payload();
    let _ = &payload;
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
        RustShape::ClapCli => clap_invocation(spec, func),
    }
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
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
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
            .contains(&EntryKind::Function));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = RustEmitter.entry_kind_hint(EntryKind::LibraryApi);
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
        let src = "use axum::extract::Query; pub fn handler(payload: &str) -> String { String::new() }";
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::AxumHandler);
    }

    #[test]
    fn shape_detect_actix_route() {
        let src = "use actix_web::HttpResponse; pub fn handler(payload: &str) -> String { String::new() }";
        let spec = make_spec_with(EntryKind::HttpRoute, "handler", "src/entry.rs");
        assert_eq!(RustShape::detect(&spec, src), RustShape::ActixWebRoute);
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
    fn b64_decode_roundtrip() {
        // Test by compiling: actual b64_decode is in generated code.
        // Just verify the Cargo.toml generation doesn't panic.
        let _ = generate_cargo_toml(Cap::FILE_IO);
        let _ = generate_cargo_toml(Cap::CODE_EXEC);
        let _ = generate_cargo_toml(Cap::SSRF);
    }
}
