//! Go harness emitter.
//!
//! Phase 15 (Track B Go vertical) replaces the single legacy `emit` body
//! with dispatch over [`GoShape`] — the cross product of [`EntryKind`]
//! and a lightweight per-file shape detector that inspects the entry
//! file for `net/http` handler signatures, gin context handlers,
//! `flag.Parse` CLIs, and `func(args ...) error` fuzz harnesses.
//!
//! Each shape emits a single `main.go` that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Imports the entry package from `./entry/` and invokes the entry
//!    function via the per-shape adapter.
//!
//! Build step: `prepare_go()` in `build_sandbox.rs` runs
//! `go build -o nyx_harness .` in the workdir. The harness command is
//! updated to the compiled binary path.
//!
//! File layout in workdir:
//! ```text
//! main.go         ← harness entry point (generated)
//! go.mod          ← module definition (generated)
//! entry/
//!   entry.go      ← entry function (copied from project; `package entry`)
//! ```
//!
//! Payload slot support:
//! - `PayloadSlot::Param(0)` — pass payload as `string` first argument.
//! - `PayloadSlot::EnvVar(name)` — set env var before calling entry.
//! - `PayloadSlot::QueryParam(name)` — surfaced to HandlerFunc / gin
//!   shapes as the named query parameter.
//! - `PayloadSlot::HttpBody` — surfaced to HandlerFunc / gin shapes as
//!   the request body.
//! - `PayloadSlot::Argv(n)` — appended to `os.Args` for `flag.Parse`
//!   shapes.
//! - Other slots produce `UnsupportedReason::PayloadSlotUnsupported`.
//!
//! Build container: `nyx-build-go:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for Go.  Method bodies delegate to the
/// existing free functions in this module.
pub struct GoEmitter;

/// Entry kinds the Go emitter understands after Phase 15.
///
/// `HttpRoute` covers `net/http` and gin handlers.  `CliSubcommand`
/// covers `flag.Parse` CLIs.  `Function` covers plain functions and
/// fuzz harnesses.
const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::HttpRoute,
    EntryKindTag::CliSubcommand,
    EntryKindTag::ClassMethod,
    EntryKindTag::MessageHandler,
    EntryKindTag::GraphQLResolver,
];

impl LangEmitter for GoEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "go emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 15 / 19 / 20 / 21 shape dispatch"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_go(env)
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        chain_step(prev_output, terminal)
    }
}

/// Phase 26 — Go chain-step harness.
///
/// Splices the Go probe shim ([`probe_shim`]) ahead of a minimal driver
/// that reads `NYX_PREV_OUTPUT` and forwards it on stdout.  When the
/// step is the chain's terminal step the driver also calls
/// `__nyx_probe(callee, prev)` and prints the
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] so the runner flips
/// `sink_hit` for the chain.
///
/// Imports are the union of the driver imports (`fmt`, `os`) and the
/// shim's [`SHIM_IMPORTS`], deduped + sorted so `go run step.go`
/// compiles in a single command.
fn chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let imports = chain_step_imports();
    let shim = probe_shim();
    let mut driver = String::from(
        "func main() {\n    prev := os.Getenv(\"NYX_PREV_OUTPUT\")\n    fmt.Print(prev)\n",
    );
    if let Some(t) = terminal {
        let callee = go_string_literal(&t.sink_callee);
        let sentinel = go_string_literal(ChainStepHarness::SINK_HIT_SENTINEL);
        driver.push_str(&format!(
            "    __nyx_probe({callee}, prev)\n    fmt.Println({sentinel})\n",
        ));
    }
    driver.push_str("}\n");
    let source = format!("package main\n\nimport (\n{imports})\n{shim}\n{driver}");
    ChainStepHarness {
        source,
        filename: "step.go".to_owned(),
        command: vec!["go".to_owned(), "run".to_owned(), "step.go".to_owned()],
        extra_env: prev_output
            .map(|bytes| {
                vec![(
                    ChainStepHarness::PREV_OUTPUT_ENV.to_owned(),
                    String::from_utf8_lossy(bytes).into_owned(),
                )]
            })
            .unwrap_or_default(),
        extra_files: Vec::new(),
    }
}

/// Escape a string for safe Go double-quoted literal embedding.
fn go_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Sorted, deduped tab-prefixed import lines covering the driver's
/// `fmt` + `os` plus everything in [`SHIM_IMPORTS`].
fn chain_step_imports() -> String {
    let driver_imports: &[&str] = &["fmt", "os"];
    let mut all: Vec<&str> = driver_imports
        .iter()
        .copied()
        .chain(SHIM_IMPORTS.iter().copied())
        .collect();
    all.sort_unstable();
    all.dedup();
    let mut out = String::new();
    for path in &all {
        out.push('\t');
        out.push('"');
        out.push_str(path);
        out.push_str("\"\n");
    }
    out
}

// ── Phase 15: shape detector ─────────────────────────────────────────────────

/// Concrete per-file shape resolved by reading the entry source.
///
/// One harness template per variant.  When the entry file is unreadable
/// or no marker fires the detector defaults to [`GoShape::Generic`],
/// preserving the pre-Phase-15 behaviour (direct `entry.Func(payload)`
/// call).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoShape {
    /// `func(w http.ResponseWriter, r *http.Request)`.  Harness builds
    /// a `httptest.NewRequest` + `httptest.NewRecorder` and dispatches
    /// the handler.
    HttpHandlerFunc,
    /// `func(c *gin.Context)`.  Harness constructs a minimal
    /// `gin.Context` stub and dispatches.  Fixture supplies the gin
    /// stub package so the toolchain compiles without a real gin dep.
    GinHandler,
    /// Phase 17 — Track L.15.  Route-bound gin handler dispatched
    /// through `httptest.NewServer` + a real-stack `gin.Engine.GET`
    /// route registration.  Emits a `NYX_GIN_TEST=1` toolchain
    /// marker on stdout so the verifier can confirm the framework
    /// dispatcher fired; v1 falls back to the [`Self::GinHandler`]
    /// in-process invocation pattern.
    GinRoute,
    /// Phase 17 — Track L.15.  `echo.Echo.GET` route handler
    /// dispatched through `httptest.NewServer`.  Emits a
    /// `NYX_ECHO_TEST=1` toolchain marker; v1 invocation re-uses the
    /// httptest dispatch pattern but skips the real `echo.New()`
    /// boot.
    EchoRoute,
    /// Phase 17 — Track L.15.  `fiber.App.Get` route handler
    /// dispatched through `httptest.NewServer`.  Emits a
    /// `NYX_FIBER_TEST=1` toolchain marker.
    FiberRoute,
    /// Phase 17 — Track L.15.  `chi.Router.Get` route handler
    /// dispatched through `httptest.NewServer`.  Emits a
    /// `NYX_CHI_TEST=1` toolchain marker.
    ChiRoute,
    /// `flag.Parse`-driven CLI.  Harness sets `os.Args` to embed the
    /// payload then invokes the entry function (typically `Main` /
    /// `Run`).
    FlagParseCli,
    /// Fuzz-style harness: `func(args ...) error` taking `[]byte`-ish
    /// inputs.  Harness invokes with `[]byte(payload)`.
    FuzzVariadic,
    /// Generic free function — pre-Phase-15 default.  Harness calls
    /// `entry.Func(payload)` directly.
    Generic,
}

impl GoShape {
    /// Detect the shape from `(spec, source)`.  `source` is the literal
    /// bytes of the entry file (best-effort — empty string falls back
    /// to [`Self::Generic`]).
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let entry = spec.entry_name.as_str();
        let kind = spec.entry_kind.tag();

        let has_http_handler =
            source.contains("http.ResponseWriter") && source.contains("*http.Request");
        let has_gin_import =
            source.contains("github.com/gin-gonic/gin") || source.contains("// nyx-shape: gin");
        let has_gin_ctx = source.contains("gin.Context") || source.contains("*gin.Context");
        let has_echo = source.contains("github.com/labstack/echo")
            || source.contains("echo.New")
            || source.contains("echo.Context")
            || source.contains("// nyx-shape: echo");
        let has_fiber = source.contains("github.com/gofiber/fiber")
            || source.contains("fiber.New")
            || source.contains("fiber.Ctx")
            || source.contains("// nyx-shape: fiber");
        let has_chi = source.contains("github.com/go-chi/chi")
            || source.contains("chi.NewRouter")
            || source.contains("// nyx-shape: chi");
        let has_flag_parse = source.contains("flag.Parse()") || source.contains("flag.Parse(");
        let has_fuzz_signature = source.contains("[]byte")
            && (entry.starts_with("Fuzz") || source.contains("// nyx-shape: fuzz"));

        // Phase 17 framework variants win over the legacy generic
        // gin / http shapes.  When the source declares a route at
        // `r.Verb("/path", target)`, prefer the framework shape so
        // the harness emits the correct toolchain marker.
        if has_chi {
            return Self::ChiRoute;
        }
        if has_fiber {
            return Self::FiberRoute;
        }
        if has_echo {
            return Self::EchoRoute;
        }
        if has_gin_import {
            return Self::GinRoute;
        }
        if has_gin_ctx {
            return Self::GinHandler;
        }
        if has_http_handler {
            return Self::HttpHandlerFunc;
        }
        if has_flag_parse {
            return Self::FlagParseCli;
        }
        if has_fuzz_signature {
            return Self::FuzzVariadic;
        }
        if kind == EntryKindTag::HttpRoute {
            return Self::HttpHandlerFunc;
        }
        if kind == EntryKindTag::CliSubcommand {
            return Self::FlagParseCli;
        }
        Self::Generic
    }
}

/// Public wrapper to detect the shape for a finalised `HarnessSpec`,
/// reading the entry file from disk.
pub fn detect_shape(spec: &HarnessSpec) -> GoShape {
    let src = read_entry_source(&spec.entry_file);
    GoShape::detect(spec, &src)
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

/// Phase 09 — Track D.2: synthesise a `go.mod` listing every captured
/// third-party import path.  Standard-library imports are skipped via
/// [`is_go_stdlib`].
pub fn materialize_go(env: &Environment) -> RuntimeArtifacts {
    let mut artifacts = RuntimeArtifacts::new();
    let go_version = env
        .toolchain
        .version_string
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    let go_version = if go_version.is_empty() {
        "1.22".to_owned()
    } else {
        go_version
    };
    let mut deps: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut versioned: Vec<crate::dynamic::framework::runtime_deps::VersionedPackage> = Vec::new();
    if let Some(adapter) = env.framework_adapter.as_deref() {
        for dep in crate::dynamic::framework::runtime_deps::deps_for_adapter(adapter).go_modules {
            if seen.insert(dep.name.to_owned()) {
                versioned.push(*dep);
            }
        }
    }
    for d in &env.direct_deps {
        if is_go_stdlib(d) {
            continue;
        }
        if seen.insert(d.clone()) {
            deps.push(d.clone());
        }
    }
    deps.sort_unstable();

    let mut body = String::with_capacity(128);
    body.push_str("module nyx_harness\n\n");
    body.push_str(&format!("go {go_version}\n"));
    if !deps.is_empty() || !versioned.is_empty() {
        body.push_str("\nrequire (\n");
        for dep in &versioned {
            body.push_str(&format!("\t{} {}\n", dep.name, dep.version));
        }
        for d in &deps {
            body.push_str(&format!("\t{d} latest\n"));
        }
        body.push_str(")\n");
    }
    artifacts.push("go.mod", body);
    artifacts
}

fn is_go_stdlib(path: &str) -> bool {
    // Anything without a "." in the first path segment is a stdlib pkg.
    let first = path.split('/').next().unwrap_or(path);
    !first.contains('.')
}

/// Source of the `__nyx_probe` shim for the Go harness (Phase 06 —
/// Track C.1).  Variadic over `string` so callers can pass any number of
/// captured args at the sink site.
pub fn probe_shim() -> &'static str {
    r##"
// ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ──────
var __nyx_deny_substrings = []string{
    "TOKEN","SECRET","PASSWORD","PASSWD","API_KEY","APIKEY","PRIVATE_KEY",
    "CREDENTIAL","SESSION","COOKIE","AUTH","BEARER","AWS_ACCESS","AWS_SESSION",
    "GH_TOKEN","GITHUB_TOKEN","NPM_TOKEN","PYPI_TOKEN","DOCKER_PASS",
}

const __nyx_payload_limit = 16 * 1024
const __nyx_redacted = "<redacted-by-nyx-policy>"

func __nyx_scrub_env() map[string]string {
    out := map[string]string{}
    for _, e := range os.Environ() {
        idx := -1
        for i, c := range e {
            if c == '=' { idx = i; break }
        }
        if idx < 0 { continue }
        k := e[:idx]
        v := e[idx+1:]
        ku := strings.ToUpper(k)
        denied := false
        for _, n := range __nyx_deny_substrings {
            if strings.Contains(ku, n) { denied = true; break }
        }
        if denied {
            out[k] = __nyx_redacted
        } else {
            out[k] = v
        }
    }
    return out
}

func __nyx_witness(sinkCallee string, args []string) map[string]interface{} {
    payload := os.Getenv("NYX_PAYLOAD")
    pb := []byte(payload)
    if len(pb) > __nyx_payload_limit { pb = pb[:__nyx_payload_limit] }
    repr := make([]string, len(args))
    for i, a := range args { repr[i] = a }
    cwd, _ := os.Getwd()
    bytes_int := make([]int, len(pb))
    for i, b := range pb { bytes_int[i] = int(b) }
    return map[string]interface{}{
        "env_snapshot":  __nyx_scrub_env(),
        "cwd":           cwd,
        "payload_bytes": bytes_int,
        "callee":        sinkCallee,
        "args_repr":     repr,
    }
}

func __nyx_emit(rec map[string]interface{}) {
    p := os.Getenv("NYX_PROBE_PATH")
    if p == "" { return }
    b, err := json.Marshal(rec)
    if err != nil { return }
    f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil { return }
    defer f.Close()
    f.Write(b)
    f.Write([]byte("\n"))
}

func __nyx_probe(sinkCallee string, args ...string) {
    serArgs := make([]map[string]interface{}, 0, len(args))
    for _, a := range args {
        serArgs = append(serArgs, map[string]interface{}{
            "kind":  "String",
            "value": a,
        })
    }
    __nyx_emit(map[string]interface{}{
        "sink_callee":    sinkCallee,
        "args":           serArgs,
        "captured_at_ns": uint64(time.Now().UnixNano()),
        "payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
        "kind":           map[string]interface{}{"kind": "Normal"},
        "witness":        __nyx_witness(sinkCallee, args),
    })
}

// Phase 08: install a sink-site signal listener via `signal.Notify`.  Go
// can intercept SIGABRT but not SIGSEGV (the Go runtime panics on
// memory faults before user handlers see them); for SIGSEGV we rely on
// the runtime's panic catch via `recover()` inside __nyx_run_sink.
func __nyx_install_crash_guard(sinkCallee string) {
    ch := make(chan os.Signal, 1)
    signal.Notify(ch, syscall.SIGABRT, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGILL)
    go func() {
        sig := <-ch
        name := "SIGABRT"
        switch sig {
        case syscall.SIGBUS: name = "SIGBUS"
        case syscall.SIGFPE: name = "SIGFPE"
        case syscall.SIGILL: name = "SIGILL"
        }
        __nyx_emit(map[string]interface{}{
            "sink_callee":    sinkCallee,
            "args":           []interface{}{},
            "captured_at_ns": uint64(time.Now().UnixNano()),
            "payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
            "kind":           map[string]interface{}{"kind": "Crash", "signal": name},
            "witness":        __nyx_witness(sinkCallee, nil),
        })
        signal.Reset(sig)
        syscall.Kill(syscall.Getpid(), sig.(syscall.Signal))
    }()
}

// Phase 08: panic-recover hook for Go runtime-caught faults (SIGSEGV nil-
// deref, divide-by-zero treated as panic).  Call as `defer __nyx_recover_crash("callee")()`
// around the instrumented sink invocation.
func __nyx_recover_crash(sinkCallee string) func() {
    return func() {
        if r := recover(); r != nil {
            __nyx_emit(map[string]interface{}{
                "sink_callee":    sinkCallee,
                "args":           []interface{}{},
                "captured_at_ns": uint64(time.Now().UnixNano()),
                "payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
                "kind":           map[string]interface{}{"kind": "Crash", "signal": "SIGSEGV"},
                "witness":        __nyx_witness(sinkCallee, nil),
            })
            panic(r)
        }
    }
}

// Phase 10 (Track D.3) HTTP recording helper.  When the verifier
// spawned an HttpStub it publishes the side-channel log path
// through NYX_HTTP_LOG; a sink call site whose outbound request
// never reaches the on-the-wire listener (DNS-mocked,
// network-isolated sandbox, pre-flight check) can call this helper
// to surface the attempted call.  Hash-prefixed detail lines plus a
// trailing summary line match the Python / Node / PHP siblings so
// the host-side HttpStub merger parses all four streams identically.
// No-op when NYX_HTTP_LOG is unset so the same harness still runs
// cleanly under modes that did not spawn a stub.
func __nyx_stub_http_record(method, url, body string, detail map[string]string) {
    p := os.Getenv("NYX_HTTP_LOG")
    if p == "" {
        return
    }
    f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer f.Close()
    f.WriteString("# method: " + method + "\n")
    f.WriteString("# url: " + url + "\n")
    if body != "" {
        f.WriteString("# body: " + body + "\n")
    }
    for k, v := range detail {
        f.WriteString("# " + k + ": " + v + "\n")
    }
    f.WriteString(method + " " + url + "\n")
}

// Phase 10 (Track D.3) SQL recording helper.  When the verifier spawned a
// SqlStub it publishes the side-channel log path through NYX_SQL_LOG; a
// sink callsite whose query never reaches the on-the-wire SQLite engine
// (no database/sql driver imported, query pre-flighted before sql.Open,
// network-isolated sandbox) can call this helper to surface the attempted
// query.  Hash-prefixed detail lines followed by the query line so
// SqlStub::drain_events parses every language stream identically.  No-op
// when NYX_SQL_LOG is unset so the same harness still runs cleanly under
// modes that did not spawn a stub.
func __nyx_stub_sql_record(query string, detail map[string]string) {
    p := os.Getenv("NYX_SQL_LOG")
    if p == "" {
        return
    }
    f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer f.Close()
    for k, v := range detail {
        f.WriteString("# " + k + ": " + v + "\n")
    }
    f.WriteString(query)
    if !strings.HasSuffix(query, "\n") {
        f.WriteString("\n")
    }
}
"##
}

/// Emit a Go harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_)
        | PayloadSlot::EnvVar(_)
        | PayloadSlot::QueryParam(_)
        | PayloadSlot::HttpBody
        | PayloadSlot::Argv(_) => {}
        PayloadSlot::Stdin => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    // Phase 05 (Track J.3): XXE-sink short-circuit.  The Go harness
    // models `encoding/xml.Decoder` with `Strict: false` so the
    // doctype is parsed and the `<!ENTITY>` body is substituted into
    // element values, matching the brief's stated behaviour.
    if spec.expected_cap == crate::labels::Cap::XXE {
        return Ok(emit_xxe_harness(spec));
    }

    // Phase 08 (Track J.6): HEADER_INJECTION-sink short-circuit.  The
    // Go harness models `w.Header().Set("Set-Cookie", value)` and
    // records the unmodified value via a `ProbeKind::HeaderEmit`
    // probe.
    if spec.expected_cap == crate::labels::Cap::HEADER_INJECTION {
        return Ok(emit_header_injection_harness(spec));
    }

    // Phase 09 (Track J.7): OPEN_REDIRECT-sink short-circuit.  The Go
    // harness models `c.Redirect(http.StatusFound, value)` (and
    // `http.Redirect`) and records the bound `Location:` value via a
    // `ProbeKind::Redirect` probe.
    if spec.expected_cap == crate::labels::Cap::OPEN_REDIRECT {
        return Ok(emit_open_redirect_harness(spec));
    }

    // Phase 11 (Track J.9): CRYPTO weak-RNG short-circuit.  The Go
    // harness imports the fixture package directly, invokes
    // `entry.<EntryFn>(payload)`, and reduces the produced key into a
    // `ProbeKind::WeakKey { key_int }` record via reflection — int
    // returns flow through as `uint64`; `[]byte` returns get truncated
    // to the leading 8 bytes via `binary.BigEndian.Uint64` padded so a
    // 32-byte `crypto/rand.Read` key produces a magnitude well above
    // any 16-bit budget.
    if spec.expected_cap == crate::labels::Cap::CRYPTO {
        return Ok(emit_crypto_harness(spec));
    }

    // JSON_PARSE depth-bomb short-circuit.  The
    // Go harness imports the fixture under `internal/vulnentry`,
    // invokes `vulnentry.<EntryFn>(payload)`, then walks the returned
    // value iteratively and emits a
    // `ProbeKind::JsonParse { depth, excessive_depth }` probe.  The
    // fixture's `Run` returns the parsed `interface{}` (or `nil` when
    // `encoding/json.Unmarshal` fails) so the harness can drive the
    // depth walker without having to intercept the parse call site
    // itself — Go can't monkey-patch the stdlib parser and a fixture-
    // side helper would have to be co-located with the entry package.
    if spec.expected_cap == crate::labels::Cap::JSON_PARSE {
        return Ok(emit_json_parse_harness(spec));
    }

    // Phase 11 (Track J.9): UNAUTHORIZED_ID IDOR harness.  Imports the
    // fixture under `internal/vulnentry`, invokes
    // `vulnentry.<EntryFn>(payload)`, and emits a
    // `ProbeKind::IdorAccess { caller_id: "alice", owner_id: payload }`
    // probe whenever the fixture materialises a present record.  A
    // `reflect`-driven presence check (`string != ""`, non-`nil` for
    // pointer / slice / map / interface, non-zero struct) covers the
    // current `func Run(string) string` fixture shape and stays correct
    // under future return-type variations.
    if spec.expected_cap == crate::labels::Cap::UNAUTHORIZED_ID {
        return Ok(emit_unauthorized_id_harness(spec));
    }

    // Phase 11 (Track J.9): DATA_EXFIL outbound-network harness.  Go has
    // no monkey-patch hook for `http.Get` / `http.Post`, but
    // `http.DefaultTransport` is a public `RoundTripper`-typed variable
    // — replacing it before the fixture runs intercepts every default-
    // client request before any wire I/O.  The harness's
    // `nyxRoundTripper` parses the request URL host, emits a
    // `ProbeKind::OutboundNetwork { host }` probe, and returns a benign
    // empty 200 OK response so the fixture's discarded result is
    // satisfied without a real connection.
    if spec.expected_cap == crate::labels::Cap::DATA_EXFIL {
        return Ok(emit_data_exfil_harness(spec));
    }

    // ClassMethod short-circuit.  Go has no
    // classes — the dispatcher treats `class` as a top-level struct
    // declared in the entry file and `method` as a method on its
    // value or pointer receiver.  The harness instantiates a zero
    // value (`var v entry.Class`) and invokes `v.Method(payload)` via
    // reflection so an unexported method on a pointer receiver still
    // dispatches.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method_harness(class, method));
    }

    // MessageHandler short-circuit.  Picks the
    // broker loopback (Pub/Sub or NATS) by inspecting the spec's
    // framework adapter id and dispatches the payload synchronously to
    // the named handler function in the entry package.
    if let crate::evidence::EntryKind::MessageHandler { queue, .. } = &spec.entry_kind {
        return Ok(emit_message_handler_harness(spec, queue));
    }

    // GraphQLResolver short-circuit (gqlgen).
    if let crate::evidence::EntryKind::GraphQLResolver { type_name, field } = &spec.entry_kind {
        return Ok(emit_graphql_resolver_harness(
            spec,
            &spec.entry_name,
            type_name,
            field,
        ));
    }

    let entry_source = read_entry_source(&spec.entry_file);
    let shape = GoShape::detect(spec, &entry_source);
    let main_go = generate_main_go(spec, shape);
    let go_mod = generate_go_mod_for_spec(shape, spec);

    let mut extra_files = vec![("go.mod".to_owned(), go_mod)];
    // Phase 15: GinHandler shape stages a minimal gin stub package so
    // the toolchain can compile the harness without pulling real gin.
    if matches!(shape, GoShape::GinHandler) {
        extra_files.push(("entry/gin/gin.go".to_owned(), gin_stub_pkg()));
    }

    Ok(HarnessSource {
        source: main_go,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files,
        entry_subpath: Some("entry/entry.go".to_owned()),
    })
}

/// Phase 05 — Track J.3 XXE harness for Go (`encoding/xml.Decoder`
/// with `Strict: false`).
///
/// Reads `NYX_PAYLOAD`, parses it with stdlib `encoding/xml.Decoder`,
/// captures the DOCTYPE `Directive` token, and walks the parser's
/// `Token()` stream.  Go's stdlib decoder does not auto-resolve
/// external entities (safe-by-default), so we detect the resolution
/// boundary by observing the parser's reaction: an `&xxx;` reference
/// to a SYSTEM entity declared in the DOCTYPE either errors out
/// (strict mode) or surfaces in `CharData` — both are real parser
/// hooks.  Writes a `ProbeKind::Xxe` probe whose `entity_expanded`
/// flag tracks whether the parser saw such a reference.  Standalone
/// `main.go` — does not pull the entry package.
pub fn emit_xxe_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod(GoShape::Generic);
    let source = format!(
        r##"// Nyx dynamic harness — XXE encoding/xml.Decoder (Phase 05 / Track J.3).
package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

{shim}

// nyxBuildXxeDocument builds the XML document fed into the decoder.
// Two shapes (Phase 05 OOB closure, 2026-05-21):
//   - URL-form NYX_PAYLOAD (`http://...` / `https://...`): treat as
//     the SYSTEM URL of an external entity and wrap into a canonical
//     XXE DTD.  When the URL points at loopback, perform a real GET so
//     the OOB listener observes the per-finding nonce callback.
//   - Anything else: treat as the full XML document (existing Phase 05
//     shape).
func nyxBuildXxeDocument(payload string) string {{
	if strings.HasPrefix(payload, "http://") || strings.HasPrefix(payload, "https://") {{
		if strings.HasPrefix(payload, "http://127.0.0.1") ||
			strings.HasPrefix(payload, "http://host-gateway") ||
			strings.HasPrefix(payload, "http://localhost") {{
			client := &http.Client{{Timeout: 2 * time.Second}}
			if resp, err := client.Get(payload); err == nil {{
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}}
		}}
		escaped := strings.ReplaceAll(payload, "&", "&amp;")
		escaped = strings.ReplaceAll(escaped, "\"", "&quot;")
		escaped = strings.ReplaceAll(escaped, "<", "&lt;")
		return "<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n  <!ENTITY xxe SYSTEM \"" + escaped + "\">\n]>\n<data>&xxe;</data>"
	}}
	return payload
}}

func nyxXmlParse(payload string) bool {{
	// Real parser hook: walk Go's encoding/xml.Decoder token stream.
	// The decoder parses <!DOCTYPE name [<!ENTITY x SYSTEM "uri">]>
	// as an xml.Directive token whose bytes carry the literal ENTITY
	// declaration.  When the body subsequently references `&x;` and
	// no Entity map is registered, the decoder raises an
	// "invalid character entity" error — that error IS the parser's
	// resolution boundary firing.
	expanded := false
	sawSystem := false
	doc := nyxBuildXxeDocument(payload)
	decoder := xml.NewDecoder(strings.NewReader(doc))
	for {{
		tok, err := decoder.Token()
		if err != nil {{
			if err != io.EOF && sawSystem && strings.Contains(err.Error(), "entity") {{
				expanded = true
			}}
			break
		}}
		if d, ok := tok.(xml.Directive); ok {{
			b := []byte(d)
			if bytes.Contains(b, []byte("ENTITY")) && bytes.Contains(b, []byte("SYSTEM")) {{
				sawSystem = true
			}}
		}}
	}}
	return expanded
}}

func nyxWriteXxeProbe(payload string, expanded bool) {{
	__nyx_emit(map[string]interface{{}}{{
		"sink_callee":    "xml.Decoder.Decode",
		"args":           []map[string]interface{{}}{{{{"kind": "String", "value": payload}}}},
		"captured_at_ns": uint64(time.Now().UnixNano()),
		"payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
		"kind":           map[string]interface{{}}{{"kind": "Xxe", "entity_expanded": expanded}},
		"witness":        __nyx_witness("xml.Decoder.Decode", []string{{payload}}),
	}})
}}

func main() {{
	__nyx_install_crash_guard("xml.Decoder.Decode")
	defer __nyx_recover_crash("xml.Decoder.Decode")()
	payload := os.Getenv("NYX_PAYLOAD")
	expanded := nyxXmlParse(payload)
	nyxWriteXxeProbe(payload, expanded)
	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"entity_expanded": expanded}})
	fmt.Println(string(body))
}}
"##
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files: vec![("go.mod".to_owned(), go_mod)],
        // Park the fixture under `entry/` so `go build .` only picks up
        // the synthetic `main.go` — fixtures declare `package vuln` /
        // `package benign`, which would otherwise collide with the
        // harness's `package main` and break the build.
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

/// Phase 08 — Track J.6 header-injection harness for Go
/// (`http.ResponseWriter.Header().Set`).
///
/// Tier (a): when the fixture imports `net/http` and exposes a
/// `func <Name>(w http.ResponseWriter, value string)`, the harness
/// rewrites the fixture's `package <X>` declaration to
/// `package vulnentry`, stages the rewritten copy under
/// `internal/vulnentry/`, drives the fixture against
/// `httptest.NewRecorder()`, and emits one `ProbeKind::HeaderEmit`
/// probe per `(name, value)` pair captured on the response writer.
///
/// Tier (b) (fallback): when the fixture does not import `net/http`,
/// inlines a synthetic `nyxHeaderProbe("Set-Cookie", payload)` so the
/// differential oracle still flips on raw payload bytes.  Mirrors the
/// Java / Python / Node / Ruby / PHP tier-(a) + synthetic-fallback
/// dispatch pattern landed in earlier sessions.
pub fn emit_header_injection_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod(GoShape::Generic);
    let entry_fn = capitalize_first(&spec.entry_name);
    let entry_source = read_entry_source(&spec.entry_file);
    let tier_a_active = entry_source_imports_net_http(&entry_source);

    let mut extra_imports = "";
    let mut via_fixture_decl = String::new();
    let via_fixture_invoke;
    let mut extra_files = vec![("go.mod".to_owned(), go_mod)];

    if tier_a_active {
        let rewritten = rewrite_package(&entry_source, "vulnentry");
        extra_files.push(("internal/vulnentry/vulnentry.go".to_owned(), rewritten));
        extra_imports =
            "\t\"net/http\"\n\t\"net/http/httptest\"\n\n\t\"nyx-harness/internal/vulnentry\"\n";
        via_fixture_decl = format!(
            r##"func nyxHeaderViaFixture(payload string) bool {{
	defer func() {{ _ = recover() }}()
	rec := httptest.NewRecorder()
	vulnentry.{entry_fn}(rec, payload)
	fired := false
	for name, values := range rec.Header() {{
		for _, value := range values {{
			nyxHeaderProbe(name, value)
			fired = true
		}}
	}}
	_ = http.StatusOK
	return fired
}}

"##
        );
        via_fixture_invoke = "\tif !nyxHeaderViaFixture(payload) {\n\t\tnyxHeaderProbe(\"Set-Cookie\", payload)\n\t}\n".to_owned();
    } else {
        via_fixture_invoke = "\tnyxHeaderProbe(\"Set-Cookie\", payload)\n".to_owned();
    }

    let source = format!(
        r##"// Nyx dynamic harness — HEADER_INJECTION http.ResponseWriter.Header().Set (Phase 08 / Track J.6).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
{extra_imports})

{shim}

func nyxHeaderProbe(name, value string) {{
	__nyx_emit(map[string]interface{{}}{{
		"sink_callee": "http.ResponseWriter.Header.Set",
		"args": []map[string]interface{{}}{{
			{{"kind": "String", "value": name}},
			{{"kind": "String", "value": value}},
		}},
		"captured_at_ns": uint64(time.Now().UnixNano()),
		"payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
		"kind":           map[string]interface{{}}{{"kind": "HeaderEmit", "name": name, "value": value, "protocol": "in-process"}},
		"witness":        __nyx_witness("http.ResponseWriter.Header.Set", []string{{name, value}}),
	}})
}}

{via_fixture_decl}func main() {{
	__nyx_install_crash_guard("http.ResponseWriter.Header.Set")
	defer __nyx_recover_crash("http.ResponseWriter.Header.Set")()
	payload := os.Getenv("NYX_PAYLOAD")
{via_fixture_invoke}	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"payload_len": len(payload)}})
	fmt.Println(string(body))
}}
"##
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files,
        // Park the raw fixture under `entry/` so `go build .` ignores
        // it (the directory is never imported by main).  When tier (a)
        // fires, the rewritten copy lives under `internal/vulnentry/`
        // with `package vulnentry` so main.go can import it directly.
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

/// Tier-(a) gate for HEADER_INJECTION + OPEN_REDIRECT: the fixture
/// must import `net/http` (header injection) or otherwise expose the
/// stdlib `http.ResponseWriter` / `http.Request` surface.  Returns
/// `true` for any `import "net/http"` style declaration.
fn entry_source_imports_net_http(src: &str) -> bool {
    src.contains("\"net/http\"")
}

/// Rewrite the first `^package <ident>$` line in `src` to
/// `package <target>`.  Tier-(a) harnesses use this to normalise
/// per-fixture package names (`package vuln` / `package benign`) to a
/// fixed name the synthetic main.go can import.  Returns the input
/// unchanged when no `package` line is found (best-effort: the build
/// will fail loudly downstream).
fn rewrite_package(src: &str, target: &str) -> String {
    let mut out = String::with_capacity(src.len() + 16);
    let mut rewrote = false;
    for line in src.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !rewrote
            && let Some(rest) = trimmed.strip_prefix("package ")
            && !rest.trim().is_empty()
        {
            out.push_str("package ");
            out.push_str(target);
            // Preserve original line ending.
            if line.ends_with("\r\n") {
                out.push_str("\r\n");
            } else if line.ends_with('\n') {
                out.push('\n');
            }
            rewrote = true;
            continue;
        }
        out.push_str(line);
    }
    out
}

/// Phase 09 — Track J.7 open-redirect harness for Go (`gin.Context.Redirect`
/// / `http.Redirect`).
///
/// Tier (a) — gin shape: when the fixture imports
/// `github.com/gin-gonic/gin`, the harness rewrites the fixture's
/// `package <X>` to `package vulnentry`, rewrites the `gin` import to a
/// local stub path, stages the rewritten fixture + gin stub copy
/// under `internal/vulnentry/`, constructs
/// `gin.NewContext(httptest.NewRecorder(), req)`, calls
/// `vulnentry.<Run>(ctx, payload)`, and emits a `ProbeKind::Redirect`
/// probe carrying the `Location:` value the stub captured.
///
/// Tier (a) — stdlib shape: when the fixture imports `net/http`
/// directly (no gin), the same tier-(a) path runs minus the gin stub
/// and the harness calls
/// `vulnentry.<Run>(httptest.NewRecorder(), <req>, payload)`.
///
/// Tier (b) (fallback): when neither gate fires, emits a synthetic
/// `nyxRedirectProbe(payload, "example.com")` so the differential
/// oracle still flips on the raw payload.
pub fn emit_open_redirect_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod(GoShape::Generic);
    let entry_fn = capitalize_first(&spec.entry_name);
    let entry_source = read_entry_source(&spec.entry_file);
    let imports_gin = entry_source.contains("gin-gonic/gin");
    let imports_net_http = entry_source_imports_net_http(&entry_source);

    let mut extra_imports = String::new();
    let mut via_fixture_decl = String::new();
    let mut via_fixture_invoke = String::new();
    let mut extra_files = vec![("go.mod".to_owned(), go_mod)];

    if imports_gin {
        // Rewrite package + gin import to local stub.
        let rewritten = rewrite_package(&entry_source, "vulnentry");
        let rewritten = rewritten.replace(
            "\"github.com/gin-gonic/gin\"",
            "\"nyx-harness/internal/vulnentry/gin\"",
        );
        extra_files.push(("internal/vulnentry/vulnentry.go".to_owned(), rewritten));
        extra_files.push(("internal/vulnentry/gin/gin.go".to_owned(), gin_stub_pkg()));
        extra_imports.push_str("\t\"net/http\"\n\t\"net/http/httptest\"\n\n\t\"nyx-harness/internal/vulnentry\"\n\t\"nyx-harness/internal/vulnentry/gin\"\n");
        via_fixture_decl.push_str(&format!(
            r##"func nyxRedirectViaFixture(payload string) (string, bool) {{
	defer func() {{ _ = recover() }}()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", strings.NewReader(""))
	ctx := gin.NewContext(rec, req)
	vulnentry.{entry_fn}(ctx, payload)
	loc := rec.Header().Get("Location")
	if loc == "" {{
		return "", false
	}}
	_ = http.StatusOK
	return loc, true
}}

"##
        ));
        via_fixture_invoke.push_str(
            "\tif loc, ok := nyxRedirectViaFixture(payload); ok {\n\t\tnyxRedirectProbe(loc, requestHost)\n\t\tnyxFollowLocation(loc)\n\t} else {\n\t\tnyxRedirectProbe(payload, requestHost)\n\t\tnyxFollowLocation(payload)\n\t}\n",
        );
    } else if imports_net_http {
        // Plain stdlib `http.Redirect(w, r, value, status)` fixture.
        let rewritten = rewrite_package(&entry_source, "vulnentry");
        extra_files.push(("internal/vulnentry/vulnentry.go".to_owned(), rewritten));
        extra_imports.push_str(
            "\t\"net/http\"\n\t\"net/http/httptest\"\n\n\t\"nyx-harness/internal/vulnentry\"\n",
        );
        via_fixture_decl.push_str(&format!(
            r##"func nyxRedirectViaFixture(payload string) (string, bool) {{
	defer func() {{ _ = recover() }}()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", strings.NewReader(""))
	vulnentry.{entry_fn}(rec, req, payload)
	loc := rec.Header().Get("Location")
	if loc == "" {{
		return "", false
	}}
	_ = http.StatusOK
	return loc, true
}}

"##
        ));
        via_fixture_invoke.push_str(
            "\tif loc, ok := nyxRedirectViaFixture(payload); ok {\n\t\tnyxRedirectProbe(loc, requestHost)\n\t\tnyxFollowLocation(loc)\n\t} else {\n\t\tnyxRedirectProbe(payload, requestHost)\n\t\tnyxFollowLocation(payload)\n\t}\n",
        );
    } else {
        // Tier-(b) fallback gate doesn't import net/http, but the OOB
        // follower itself needs it.  Pull the stdlib net/http surface
        // unconditionally so `nyxFollowLocation` compiles.
        extra_imports.push_str("\t\"net/http\"\n");
        via_fixture_invoke
            .push_str("\tnyxRedirectProbe(payload, requestHost)\n\tnyxFollowLocation(payload)\n");
    }

    let source = format!(
        r##"// Nyx dynamic harness — OPEN_REDIRECT c.Redirect (Phase 09 / Track J.7).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
{extra_imports})

{shim}

func nyxRedirectProbe(location, requestHost string) {{
	__nyx_emit(map[string]interface{{}}{{
		"sink_callee": "gin.Context.Redirect",
		"args": []map[string]interface{{}}{{
			{{"kind": "String", "value": location}},
		}},
		"captured_at_ns": uint64(time.Now().UnixNano()),
		"payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
		"kind":           map[string]interface{{}}{{"kind": "Redirect", "location": location, "request_host": requestHost}},
		"witness":        __nyx_witness("gin.Context.Redirect", []string{{location}}),
	}})
}}

// Phase 09 OOB closure: when the captured Location is a loopback URL,
// follow it with a real GET so the OOB listener observes the per-finding
// nonce.  Skips non-loopback hosts and non-HTTP schemes (no real network
// egress).  Best-effort: errors do not propagate; the listener may still
// record the TCP connect before the read fails.
func nyxFollowLocation(location string) {{
	if location == "" {{
		return
	}}
	if !(strings.HasPrefix(location, "http://127.0.0.1") ||
		strings.HasPrefix(location, "http://localhost") ||
		strings.HasPrefix(location, "http://host-gateway")) {{
		return
	}}
	client := &http.Client{{Timeout: 2 * time.Second}}
	resp, err := client.Get(location)
	if err != nil {{
		return
	}}
	defer resp.Body.Close()
	buf := make([]byte, 1)
	_, _ = resp.Body.Read(buf)
}}

{via_fixture_decl}func main() {{
	__nyx_install_crash_guard("gin.Context.Redirect")
	defer __nyx_recover_crash("gin.Context.Redirect")()
	payload := os.Getenv("NYX_PAYLOAD")
	requestHost := "example.com"
{via_fixture_invoke}	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"request_host": requestHost}})
	fmt.Println(string(body))
}}
"##
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files,
        // Park the raw fixture under `entry/` so `go build .` ignores
        // it (the directory is never imported by main).  Tier (a)
        // ships the rewritten copy under `internal/vulnentry/`.
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

fn generate_main_go(spec: &HarnessSpec, shape: GoShape) -> String {
    let entry_fn = capitalize_first(&spec.entry_name);
    let pre_call = pre_call_setup(spec);
    let imports = imports_for_shape(shape);
    let invocation = invoke_for_shape(spec, shape, &entry_fn);
    let shim = probe_shim();

    format!(
        r#"// Nyx dynamic harness — auto-generated, do not edit (Phase 15 — GoShape::{shape:?}).
package main

import (
{imports})
{shim}
func main() {{
	payload := nyxPayload()
	_ = payload
	__nyx_install_crash_guard("{entry_fn}")
	defer __nyx_recover_crash("{entry_fn}")()
{pre_call}{invocation}
}}

func nyxPayload() string {{
	if v := os.Getenv("NYX_PAYLOAD"); v != "" {{
		return v
	}}
	if b64 := os.Getenv("NYX_PAYLOAD_B64"); b64 != "" {{
		if data, err := base64.StdEncoding.DecodeString(b64); err == nil {{
			return string(data)
		}}
	}}
	return ""
}}
"#,
        shape = shape,
        imports = imports,
        pre_call = pre_call,
        invocation = invocation,
        shim = shim,
        entry_fn = entry_fn,
    )
}

/// Imports required by the spliced probe shim.  Always present, deduped
/// against per-shape additions in [`imports_for_shape`].
const SHIM_IMPORTS: &[&str] = &["encoding/json", "os/signal", "strings", "syscall", "time"];

fn imports_for_shape(shape: GoShape) -> String {
    let stdlib_base: &[&str] = &["encoding/base64", "os"];
    let shape_extras: &[&str] = match shape {
        GoShape::Generic | GoShape::FlagParseCli | GoShape::FuzzVariadic => &[],
        GoShape::HttpHandlerFunc => &["net/http", "net/http/httptest"],
        GoShape::GinHandler => &["net/http", "net/http/httptest"],
        GoShape::GinRoute | GoShape::EchoRoute | GoShape::ChiRoute => {
            &["fmt", "net/http", "net/http/httptest", "net/url"]
        }
        GoShape::FiberRoute => &["fmt", "net/http", "net/url"],
    };
    let local_pkgs: &[&str] = match shape {
        GoShape::GinHandler => &["nyx-harness/entry", "nyx-harness/entry/gin"],
        GoShape::GinRoute => &["github.com/gin-gonic/gin", "nyx-harness/entry"],
        GoShape::EchoRoute => &["github.com/labstack/echo/v4", "nyx-harness/entry"],
        GoShape::FiberRoute => &["github.com/gofiber/fiber/v2", "nyx-harness/entry"],
        GoShape::ChiRoute => &["github.com/go-chi/chi/v5", "nyx-harness/entry"],
        _ => &["nyx-harness/entry"],
    };

    let mut stdlib: Vec<&str> = stdlib_base
        .iter()
        .copied()
        .chain(shape_extras.iter().copied())
        .chain(SHIM_IMPORTS.iter().copied())
        .collect();
    stdlib.sort_unstable();
    stdlib.dedup();

    let mut out = String::new();
    for path in &stdlib {
        out.push('\t');
        out.push('"');
        out.push_str(path);
        out.push_str("\"\n");
    }
    out.push('\n');
    for path in local_pkgs {
        out.push('\t');
        out.push('"');
        out.push_str(path);
        out.push_str("\"\n");
    }
    out
}

fn pre_call_setup(spec: &HarnessSpec) -> String {
    match &spec.payload_slot {
        PayloadSlot::EnvVar(name) => format!("\tos.Setenv({name:?}, payload)\n"),
        PayloadSlot::Argv(n) => {
            let pads = (0..*n)
                .map(|_| "\"\"".to_owned())
                .collect::<Vec<_>>()
                .join(", ");
            if pads.is_empty() {
                "\tos.Args = []string{\"nyx_harness\", payload}\n".to_string()
            } else {
                format!("\tos.Args = []string{{\"nyx_harness\", {pads}, payload}}\n")
            }
        }
        _ => String::new(),
    }
}

fn invoke_for_shape(spec: &HarnessSpec, shape: GoShape, entry_fn: &str) -> String {
    let query_param = match &spec.payload_slot {
        PayloadSlot::QueryParam(name) => name.clone(),
        _ => "payload".to_owned(),
    };
    let use_body = matches!(&spec.payload_slot, PayloadSlot::HttpBody);

    match shape {
        GoShape::Generic => format!("\tentry.{entry_fn}(payload)\n"),
        GoShape::HttpHandlerFunc => {
            let body_setup = if use_body {
                "\treq := httptest.NewRequest(\"POST\", \"/\", strings.NewReader(payload))\n"
            } else {
                ""
            };
            let url_setup = if use_body {
                String::new()
            } else {
                format!(
                    "\treq := httptest.NewRequest(\"GET\", \"/?{q}=\"+payload, strings.NewReader(\"\"))\n",
                    q = query_param
                )
            };
            format!(
                "{body_setup}{url_setup}\trw := httptest.NewRecorder()\n\tentry.{entry_fn}(rw, req)\n\t_ = http.StatusOK\n",
            )
        }
        GoShape::GinHandler => {
            let setup = if use_body {
                "\treq := httptest.NewRequest(\"POST\", \"/\", strings.NewReader(payload))\n"
            } else {
                "\treq := httptest.NewRequest(\"GET\", \"/?payload=\"+payload, strings.NewReader(\"\"))\n"
            };
            format!(
                "{setup}\trw := httptest.NewRecorder()\n\tctx := gin.NewContext(rw, req)\n\tentry.{entry_fn}(ctx)\n\t_ = http.StatusOK\n",
            )
        }
        GoShape::FlagParseCli => format!("\tentry.{entry_fn}()\n"),
        GoShape::FuzzVariadic => format!("\t_ = entry.{entry_fn}([]byte(payload))\n"),
        GoShape::GinRoute => framework_route_invocation(
            spec,
            GoShape::GinRoute,
            "NYX_GIN_TEST=1",
            entry_fn,
            use_body,
            &query_param,
        ),
        GoShape::EchoRoute => framework_route_invocation(
            spec,
            GoShape::EchoRoute,
            "NYX_ECHO_TEST=1",
            entry_fn,
            use_body,
            &query_param,
        ),
        GoShape::FiberRoute => framework_route_invocation(
            spec,
            GoShape::FiberRoute,
            "NYX_FIBER_TEST=1",
            entry_fn,
            use_body,
            &query_param,
        ),
        GoShape::ChiRoute => framework_route_invocation(
            spec,
            GoShape::ChiRoute,
            "NYX_CHI_TEST=1",
            entry_fn,
            use_body,
            &query_param,
        ),
    }
}

fn framework_route_invocation(
    _spec: &HarnessSpec,
    shape: GoShape,
    marker: &str,
    entry_fn: &str,
    use_body: bool,
    query_param: &str,
) -> String {
    let target_setup = if use_body {
        "\ttarget := \"/run\"\n".to_owned()
    } else {
        format!(
            "\ttarget := \"/run?{q}=\" + url.QueryEscape(payload)\n",
            q = query_param
        )
    };
    let req_setup = if use_body {
        "\treq := httptest.NewRequest(\"POST\", target, strings.NewReader(payload))\n"
    } else if matches!(shape, GoShape::FiberRoute) {
        "\treq, _ := http.NewRequest(\"GET\", target, nil)\n"
    } else {
        "\treq := httptest.NewRequest(\"GET\", target, strings.NewReader(\"\"))\n"
    };
    let dispatch = match shape {
        GoShape::GinRoute => format!(
            "\tr := gin.New()\n\tr.GET(\"/run\", entry.{entry_fn})\n\trw := httptest.NewRecorder()\n\tr.ServeHTTP(rw, req)\n\t_ = http.StatusOK\n"
        ),
        GoShape::EchoRoute => format!(
            "\te := echo.New()\n\te.GET(\"/run\", entry.{entry_fn})\n\trw := httptest.NewRecorder()\n\te.ServeHTTP(rw, req)\n\t_ = http.StatusOK\n"
        ),
        GoShape::FiberRoute => format!(
            "\tapp := fiber.New()\n\tapp.Get(\"/run\", entry.{entry_fn})\n\t_, _ = app.Test(req)\n\t_ = http.StatusOK\n"
        ),
        GoShape::ChiRoute => format!(
            "\tr := chi.NewRouter()\n\tr.Get(\"/run\", entry.{entry_fn})\n\trw := httptest.NewRecorder()\n\tr.ServeHTTP(rw, req)\n\t_ = http.StatusOK\n"
        ),
        _ => unreachable!("framework_route_invocation only handles framework route shapes"),
    };
    format!("\tfmt.Println(\"{marker}\")\n{target_setup}{req_setup}{dispatch}")
}

fn generate_go_mod(shape: GoShape) -> String {
    render_go_mod(shape_go_deps(shape), &[])
}

fn generate_go_mod_for_spec(shape: GoShape, spec: &HarnessSpec) -> String {
    let adapter_deps = spec
        .framework
        .as_ref()
        .map(|binding| {
            crate::dynamic::framework::runtime_deps::deps_for_adapter(&binding.adapter).go_modules
        })
        .unwrap_or(&[]);
    render_go_mod(shape_go_deps(shape), adapter_deps)
}

fn shape_go_deps(shape: GoShape) -> &'static [(&'static str, &'static str)] {
    match shape {
        GoShape::GinRoute => &[("github.com/gin-gonic/gin", "v1.10.0")],
        GoShape::EchoRoute => &[("github.com/labstack/echo/v4", "v4.12.0")],
        GoShape::FiberRoute => &[("github.com/gofiber/fiber/v2", "v2.52.5")],
        GoShape::ChiRoute => &[("github.com/go-chi/chi/v5", "v5.0.12")],
        _ => &[],
    }
}

fn render_go_mod(
    shape_deps: &[(&str, &str)],
    adapter_deps: &[crate::dynamic::framework::runtime_deps::VersionedPackage],
) -> String {
    let mut out = "module nyx-harness\n\ngo 1.21\n".to_owned();
    if !shape_deps.is_empty() || !adapter_deps.is_empty() {
        out.push_str("\nrequire (\n");
        let mut seen = std::collections::HashSet::new();
        for (module, version) in shape_deps {
            seen.insert(*module);
            out.push('\t');
            out.push_str(module);
            out.push(' ');
            out.push_str(version);
            out.push('\n');
        }
        for dep in adapter_deps {
            if !seen.insert(dep.name) {
                continue;
            }
            out.push('\t');
            out.push_str(dep.name);
            out.push(' ');
            out.push_str(dep.version);
            out.push('\n');
        }
        out.push_str(")\n");
    }
    out
}

/// Phase 11 (Track J.9) CRYPTO harness for Go.
///
/// Reads `NYX_PAYLOAD`, imports the fixture under
/// `internal/vulnentry`, invokes `vulnentry.<EntryFn>(payload)`, and
/// emits a [`crate::dynamic::probe::ProbeKind::WeakKey`] probe whose
/// `key_int` is derived from the returned key.  `int` returns flow
/// through as `uint64`; `[]byte` returns get reduced to the leading 8
/// bytes via `binary.BigEndian.Uint64` (zero-padded to 8 bytes when
/// the slice is shorter), so a `crypto/rand.Read` benign control
/// trivially overshoots the predicate's 16-bit budget while the
/// `math/rand.Intn(0x10000)` vuln stays inside it.  Falls back to a
/// payload-byte view when the fixture cannot be invoked so the
/// universal sink-hit path still fires.
pub fn emit_crypto_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod(GoShape::Generic);
    let entry_fn = capitalize_first(&spec.entry_name);
    let entry_source = read_entry_source(&spec.entry_file);
    let mut extra_files = vec![("go.mod".to_owned(), go_mod)];
    let tier_a_active = !entry_source.is_empty();
    let (extra_imports, via_fixture_decl, via_fixture_invoke) = if tier_a_active {
        let rewritten = rewrite_package(&entry_source, "vulnentry");
        extra_files.push(("internal/vulnentry/vulnentry.go".to_owned(), rewritten));
        let decl = format!(
            r##"func nyxCryptoViaFixture(payload string) (uint64, bool) {{
	defer func() {{ _ = recover() }}()
	produced := vulnentry.{entry_fn}(payload)
	keyInt, ok := nyxKeyToInt(produced)
	return keyInt, ok
}}

func nyxKeyToInt(value interface{{}}) (uint64, bool) {{
	v := reflect.ValueOf(value)
	if !v.IsValid() {{
		return 0, false
	}}
	switch v.Kind() {{
	case reflect.Bool:
		if v.Bool() {{
			return 1, true
		}}
		return 0, true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return uint64(v.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint(), true
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {{
			b := v.Bytes()
			var buf [8]byte
			n := len(b)
			if n > 8 {{
				n = 8
			}}
			copy(buf[8-n:], b[:n])
			return binary.BigEndian.Uint64(buf[:]), true
		}}
		return 0, false
	case reflect.String:
		s := v.String()
		var buf [8]byte
		n := len(s)
		if n > 8 {{
			n = 8
		}}
		copy(buf[8-n:], []byte(s)[:n])
		return binary.BigEndian.Uint64(buf[:]), true
	}}
	return 0, false
}}

"##
        );
        let invoke = "\tkeyInt, ok := nyxCryptoViaFixture(payload)\n\tif !ok {\n\t\tvar buf [8]byte\n\t\tn := len(payload)\n\t\tif n > 8 {\n\t\t\tn = 8\n\t\t}\n\t\tcopy(buf[8-n:], []byte(payload)[:n])\n\t\tkeyInt = binary.BigEndian.Uint64(buf[:])\n\t}\n\tnyxWeakKeyProbe(keyInt)\n".to_owned();
        (
            "\t\"encoding/binary\"\n\t\"reflect\"\n\n\t\"nyx-harness/internal/vulnentry\"\n",
            decl,
            invoke,
        )
    } else {
        (
            "\t\"encoding/binary\"\n",
            String::new(),
            "\tvar buf [8]byte\n\tn := len(payload)\n\tif n > 8 {\n\t\tn = 8\n\t}\n\tcopy(buf[8-n:], []byte(payload)[:n])\n\tnyxWeakKeyProbe(binary.BigEndian.Uint64(buf[:]))\n".to_owned(),
        )
    };

    let source = format!(
        r##"// Nyx dynamic harness — CRYPTO weak-RNG key entropy (Phase 11 / Track J.9).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
{extra_imports})

{shim}

func nyxWeakKeyProbe(keyInt uint64) {{
	__nyx_emit(map[string]interface{{}}{{
		"sink_callee": "__nyx_weak_key",
		"args": []map[string]interface{{}}{{
			{{"kind": "Int", "value": keyInt}},
		}},
		"captured_at_ns": uint64(time.Now().UnixNano()),
		"payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
		"kind":           map[string]interface{{}}{{"kind": "WeakKey", "key_int": keyInt}},
		"witness":        __nyx_witness("__nyx_weak_key", []string{{fmt.Sprintf("%d", keyInt)}}),
	}})
}}

{via_fixture_decl}func main() {{
	__nyx_install_crash_guard("__nyx_weak_key")
	defer __nyx_recover_crash("__nyx_weak_key")()
	payload := os.Getenv("NYX_PAYLOAD")
{via_fixture_invoke}	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"payload_len": len(payload)}})
	fmt.Println(string(body))
}}
"##
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files,
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

/// Phase 11 (Track J.9) JSON_PARSE depth-bomb harness for Go.
///
/// Imports the fixture under `internal/vulnentry`, invokes
/// `vulnentry.<EntryFn>(payload)`, and walks the returned value
/// iteratively to emit a
/// [`crate::dynamic::probe::ProbeKind::JsonParse`] probe.  The
/// fixture's `Run` is expected to call `encoding/json.Unmarshal`
/// (which is iterative in the Go stdlib so deeply-nested input never
/// panics) and return the parsed `interface{}` so the harness can
/// drive the depth walker post-parse.  Falls back to a payload-only
/// path that emits `JsonParse { depth: 0, excessive_depth: false }`
/// when the fixture source is unreachable so the universal sink-hit
/// path still fires.
pub fn emit_json_parse_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod(GoShape::Generic);
    let entry_fn = capitalize_first(&spec.entry_name);
    let entry_source = read_entry_source(&spec.entry_file);
    let mut extra_files = vec![("go.mod".to_owned(), go_mod)];
    let tier_a_active = !entry_source.is_empty();
    let (extra_imports, via_fixture_decl, via_fixture_invoke) = if tier_a_active {
        let rewritten = rewrite_package(&entry_source, "vulnentry");
        extra_files.push(("internal/vulnentry/vulnentry.go".to_owned(), rewritten));
        let decl = format!(
            r##"const nyxJsonMaxWalk = 4096

func nyxJsonCountDepth(parsed interface{{}}) int {{
	type frame struct {{
		v     interface{{}}
		depth int
	}}
	maxDepth := 0
	stack := []frame{{{{v: parsed, depth: 1}}}}
	visited := 0
	for len(stack) > 0 {{
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visited++
		if visited > nyxJsonMaxWalk {{
			break
		}}
		if f.depth > maxDepth {{
			maxDepth = f.depth
		}}
		switch cur := f.v.(type) {{
		case map[string]interface{{}}:
			for _, child := range cur {{
				stack = append(stack, frame{{v: child, depth: f.depth + 1}})
			}}
		case []interface{{}}:
			for _, child := range cur {{
				stack = append(stack, frame{{v: child, depth: f.depth + 1}})
			}}
		}}
	}}
	return maxDepth
}}

func nyxJsonParseViaFixture(payload string) (int, bool, bool) {{
	var depth int
	var excessive bool
	var invoked bool
	defer func() {{ _ = recover() }}()
	parsed := vulnentry.{entry_fn}(payload)
	invoked = true
	depth = nyxJsonCountDepth(parsed)
	excessive = depth > 64
	return depth, excessive, invoked
}}

"##
        );
        let invoke = "\tdepth, excessive, fixtureInvoked := nyxJsonParseViaFixture(payload)\n\tif !fixtureInvoked {\n\t\tdepth = 0\n\t\texcessive = false\n\t}\n\tnyxJsonParseProbe(depth, excessive)\n".to_owned();
        ("\n\t\"nyx-harness/internal/vulnentry\"\n", decl, invoke)
    } else {
        (
            "",
            String::new(),
            "\tnyxJsonParseProbe(0, false)\n".to_owned(),
        )
    };

    let source = format!(
        r##"// Nyx dynamic harness — JSON_PARSE depth checks (Phase 11 / Track J.9).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
{extra_imports})

{shim}

func nyxJsonParseProbe(depth int, excessive bool) {{
	__nyx_emit(map[string]interface{{}}{{
		"sink_callee": "json.Unmarshal",
		"args": []map[string]interface{{}}{{
			{{"kind": "Int", "value": depth}},
		}},
		"captured_at_ns": uint64(time.Now().UnixNano()),
		"payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
		"kind": map[string]interface{{}}{{
			"kind":            "JsonParse",
			"depth":           depth,
			"excessive_depth": excessive,
		}},
		"witness": __nyx_witness("json.Unmarshal", []string{{fmt.Sprintf("%d", depth)}}),
	}})
}}

{via_fixture_decl}func main() {{
	__nyx_install_crash_guard("json.Unmarshal")
	defer __nyx_recover_crash("json.Unmarshal")()
	payload := os.Getenv("NYX_PAYLOAD")
{via_fixture_invoke}	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"payload_len": len(payload)}})
	fmt.Println(string(body))
}}
"##
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files,
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

/// Phase 11 (Track J.9) UNAUTHORIZED_ID IDOR harness for Go.
///
/// Imports the fixture under `internal/vulnentry`, invokes
/// `vulnentry.<EntryFn>(payload)`, and emits a
/// [`crate::dynamic::probe::ProbeKind::IdorAccess`] probe iff the
/// fixture materialises a present record.  Presence is decided via
/// `reflect`: `string != ""`, non-`nil` for pointer / slice / map /
/// interface / channel / func, non-zero for struct.  The
/// `IdorBoundaryCrossed` predicate fires when `caller_id != owner_id`;
/// the harness pins `caller_id = "alice"` and treats the payload as
/// `owner_id`.  Falls back to a payload-only path that emits an
/// `IdorAccess(alice, payload)` probe when the fixture source is
/// unreachable so the universal sink-hit path still fires.
pub fn emit_unauthorized_id_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod(GoShape::Generic);
    let entry_fn = capitalize_first(&spec.entry_name);
    let entry_source = read_entry_source(&spec.entry_file);
    let mut extra_files = vec![("go.mod".to_owned(), go_mod)];
    let tier_a_active = !entry_source.is_empty();
    let (extra_imports, via_fixture_decl, via_fixture_invoke) = if tier_a_active {
        let rewritten = rewrite_package(&entry_source, "vulnentry");
        extra_files.push(("internal/vulnentry/vulnentry.go".to_owned(), rewritten));
        let decl = format!(
            r##"func nyxRecordPresent(v reflect.Value) bool {{
	if !v.IsValid() {{
		return false
	}}
	switch v.Kind() {{
	case reflect.String:
		return v.String() != ""
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Interface, reflect.Chan, reflect.Func:
		return !v.IsNil()
	case reflect.Struct:
		return !v.IsZero()
	default:
		return !v.IsZero()
	}}
}}

func nyxUnauthorizedIdViaFixture(payload string) bool {{
	defer func() {{ _ = recover() }}()
	produced := vulnentry.{entry_fn}(payload)
	return nyxRecordPresent(reflect.ValueOf(produced))
}}

"##
        );
        let invoke = "\tif nyxUnauthorizedIdViaFixture(payload) {\n\t\tnyxIdorAccessProbe(_NYX_CALLER_ID, payload)\n\t}\n".to_owned();
        (
            "\t\"reflect\"\n\n\t\"nyx-harness/internal/vulnentry\"\n",
            decl,
            invoke,
        )
    } else {
        (
            "",
            String::new(),
            "\tnyxIdorAccessProbe(_NYX_CALLER_ID, payload)\n".to_owned(),
        )
    };

    let source = format!(
        r##"// Nyx dynamic harness — UNAUTHORIZED_ID IDOR boundary (Phase 11 / Track J.9).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
{extra_imports})

{shim}

const _NYX_CALLER_ID = "alice"

func nyxIdorAccessProbe(caller, owner string) {{
	__nyx_emit(map[string]interface{{}}{{
		"sink_callee": "__nyx_idor_lookup",
		"args": []map[string]interface{{}}{{
			{{"kind": "String", "value": caller}},
			{{"kind": "String", "value": owner}},
		}},
		"captured_at_ns": uint64(time.Now().UnixNano()),
		"payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
		"kind": map[string]interface{{}}{{
			"kind":      "IdorAccess",
			"caller_id": caller,
			"owner_id":  owner,
		}},
		"witness": __nyx_witness("__nyx_idor_lookup", []string{{caller, owner}}),
	}})
}}

{via_fixture_decl}func main() {{
	__nyx_install_crash_guard("__nyx_idor_lookup")
	defer __nyx_recover_crash("__nyx_idor_lookup")()
	payload := os.Getenv("NYX_PAYLOAD")
{via_fixture_invoke}	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"payload_len": len(payload)}})
	fmt.Println(string(body))
}}
"##
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files,
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

/// Phase 11 (Track J.9) DATA_EXFIL outbound-network harness for Go.
///
/// Imports the fixture under `internal/vulnentry`, replaces
/// `http.DefaultTransport` and `http.DefaultClient.Transport` with a
/// `nyxRoundTripper` that captures the request URL host before any
/// wire I/O, emits a
/// [`crate::dynamic::probe::ProbeKind::OutboundNetwork`] probe, and
/// returns a benign empty 200 OK response so the fixture's discarded
/// result is satisfied without a real connection.  `http.Get` /
/// `http.Post` / `http.Client.Do` all route through `Client.transport()`
/// which falls back to `DefaultTransport` when `Client.Transport` is
/// `nil`, so the override covers the package-level helpers as well as
/// any fixture-built `&http.Client{}` whose `Transport` field stays
/// default.  The
/// [`crate::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
/// predicate fires when the captured host falls outside the loopback
/// allowlist.  Falls back to a payload-only path that emits an
/// `OutboundNetwork(payload)` probe when the fixture source is
/// unreachable so the universal sink-hit path still fires.
pub fn emit_data_exfil_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod(GoShape::Generic);
    let entry_fn = capitalize_first(&spec.entry_name);
    let entry_source = read_entry_source(&spec.entry_file);
    let mut extra_files = vec![("go.mod".to_owned(), go_mod)];
    let tier_a_active = !entry_source.is_empty();
    let (extra_imports, via_fixture_decl, via_fixture_invoke) = if tier_a_active {
        let rewritten = rewrite_package(&entry_source, "vulnentry");
        extra_files.push(("internal/vulnentry/vulnentry.go".to_owned(), rewritten));
        let decl = r##"type nyxRoundTripper struct{}

func (nyxRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := ""
	if req != nil && req.URL != nil {
		host = req.URL.Hostname()
		if host == "" {
			host = req.URL.Host
		}
	}
	if host != "" {
		nyxOutboundProbe(host)
	}
	return &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    req,
	}, nil
}

func nyxInstallHttpTransport() {
	rt := nyxRoundTripper{}
	http.DefaultTransport = rt
	http.DefaultClient = &http.Client{Transport: rt}
}

func nyxDataExfilViaFixture(payload string) {
	defer func() { _ = recover() }()
	vulnentry."##
            .to_owned()
            + &format!("{entry_fn}(payload)\n}}\n\n");
        let invoke = "\tnyxInstallHttpTransport()\n\tnyxDataExfilViaFixture(payload)\n".to_owned();
        (
            "\t\"bytes\"\n\t\"io\"\n\t\"net/http\"\n\n\t\"nyx-harness/internal/vulnentry\"\n",
            decl,
            invoke,
        )
    } else {
        (
            "",
            String::new(),
            "\tnyxOutboundProbe(payload)\n".to_owned(),
        )
    };

    let source = format!(
        r##"// Nyx dynamic harness — DATA_EXFIL outbound-host (Phase 11 / Track J.9).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
{extra_imports})

{shim}

func nyxOutboundProbe(host string) {{
	__nyx_emit(map[string]interface{{}}{{
		"sink_callee": "__nyx_mock_http",
		"args": []map[string]interface{{}}{{
			{{"kind": "String", "value": host}},
		}},
		"captured_at_ns": uint64(time.Now().UnixNano()),
		"payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
		"kind":           map[string]interface{{}}{{"kind": "OutboundNetwork", "host": host}},
		"witness":        __nyx_witness("__nyx_mock_http", []string{{host}}),
	}})
}}

{via_fixture_decl}func main() {{
	__nyx_install_crash_guard("__nyx_mock_http")
	defer __nyx_recover_crash("__nyx_mock_http")()
	payload := os.Getenv("NYX_PAYLOAD")
{via_fixture_invoke}	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"payload_len": len(payload)}})
	fmt.Println(string(body))
}}
"##
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files,
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

/// Phase 19 (Track M.1) — class-method harness for Go.
///
/// `class` is mapped to a struct type declared in `entry/entry.go`
/// and `method` to a method-on-receiver.  The harness uses reflection
/// to construct a zero value, then invokes the method with the
/// payload — supporting both value and pointer receivers.
fn emit_class_method_harness(class: &str, method: &str) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod(GoShape::Generic);
    let auto_registry = generate_auto_receiver_registry(class);
    let source = format!(
        r##"// Nyx dynamic harness — class method (Phase 19 / Track M.1).
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"nyx-harness/entry"
)

{shim}

func nyxBuildReceiver(structName string) (reflect.Value, error) {{
	// Look up the exported type by name on the entry package.  Go's
	// reflect API does not expose package-level reflection over types
	// directly, so the dispatcher uses a generated `NyxAutoReceivers`
	// registry that the harness ships into the entry package at
	// compile time (see `entry/nyx_auto_registry.go`).  Real-world
	// projects under test never need to hand-declare the registry —
	// the auto-generated file references the target type by name and
	// the Go compiler enforces the contract.
	if r, ok := entry.NyxAutoReceivers[structName]; ok {{
		return nyxPopulateReceiver(reflect.ValueOf(r), 3), nil
	}}
	return reflect.Value{{}}, fmt.Errorf("class not found: %s", structName)
}}

func nyxPopulateReceiver(v reflect.Value, depth int) reflect.Value {{
	seen := map[reflect.Type]bool{{}}
	return nyxPopulateValue(v, depth, seen)
}}

func nyxPopulateValue(v reflect.Value, depth int, seen map[reflect.Type]bool) reflect.Value {{
	if !v.IsValid() || depth < 0 {{
		return v
	}}
	if v.Kind() == reflect.Pointer {{
		if v.IsNil() {{
			if v.Type().Elem().Kind() != reflect.Struct {{
				return v
			}}
			v = reflect.New(v.Type().Elem())
		}}
		nyxPopulateStruct(v.Elem(), depth, seen)
		return v
	}}
	if v.Kind() == reflect.Struct {{
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		nyxPopulateStruct(out, depth, seen)
		return out
	}}
	return v
}}

func nyxPopulateStruct(v reflect.Value, depth int, seen map[reflect.Type]bool) {{
	if !v.IsValid() || v.Kind() != reflect.Struct || depth < 0 {{
		return
	}}
	t := v.Type()
	if seen[t] {{
		return
	}}
	seen[t] = true
	defer delete(seen, t)
	for i := 0; i < v.NumField(); i++ {{
		field := v.Field(i)
		if !field.CanSet() {{
			continue
		}}
		dep := nyxBuildValueForType(field.Type(), depth-1, seen)
		if dep.IsValid() && dep.Type().AssignableTo(field.Type()) {{
			field.Set(dep)
		}}
	}}
}}

func nyxBuildValueForType(t reflect.Type, depth int, seen map[reflect.Type]bool) reflect.Value {{
	if depth < 0 {{
		return reflect.Value{{}}
	}}
	if t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct {{
		ptr := reflect.New(t.Elem())
		nyxPopulateStruct(ptr.Elem(), depth, seen)
		return ptr
	}}
	if t.Kind() == reflect.Struct {{
		value := reflect.New(t).Elem()
		nyxPopulateStruct(value, depth, seen)
		return value
	}}
	return reflect.Value{{}}
}}

func nyxPayload() string {{
	if v := os.Getenv("NYX_PAYLOAD"); v != "" {{
		return v
	}}
	if b64 := os.Getenv("NYX_PAYLOAD_B64"); b64 != "" {{
		if data, err := base64.StdEncoding.DecodeString(b64); err == nil {{
			return string(data)
		}}
	}}
	return ""
}}

func main() {{
	payload := nyxPayload()
	__nyx_install_crash_guard("{class}.{method}")
	v, err := nyxBuildReceiver("{class}")
	if err != nil {{
		fmt.Fprintln(os.Stderr, "NYX_CLASS_NOT_FOUND: "+"{class}")
		os.Exit(78)
	}}
	m := v.MethodByName("{method}")
	if !m.IsValid() {{
		// reflect.ValueOf(receiver) returns a non-addressable Value, so
		// v.CanAddr() is always false.  Promote to an addressable copy
		// via reflect.New so pointer-receiver methods bind.
		ptr := reflect.New(v.Type())
		ptr.Elem().Set(v)
		m = ptr.MethodByName("{method}")
	}}
	if !m.IsValid() {{
		fmt.Fprintln(os.Stderr, "NYX_METHOD_NOT_FOUND: "+"{method}")
		os.Exit(78)
	}}
	defer func() {{
		if r := recover(); r != nil {{
			fmt.Fprintf(os.Stderr, "NYX_EXCEPTION: panic: %v\n", r)
		}}
	}}()
	args := make([]reflect.Value, m.Type().NumIn())
	for i := 0; i < m.Type().NumIn(); i++ {{
		if m.Type().In(i).Kind() == reflect.String {{
			args[i] = reflect.ValueOf(payload)
		}} else {{
			args[i] = reflect.Zero(m.Type().In(i))
		}}
	}}
	out := m.Call(args)
	fmt.Println("__NYX_SINK_HIT__")
	if len(out) > 0 {{
		fmt.Println(out[0].Interface())
	}}
}}
"##,
        class = class,
        method = method,
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files: vec![
            ("go.mod".to_owned(), go_mod),
            ("entry/nyx_auto_registry.go".to_owned(), auto_registry),
        ],
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

/// Generate an `entry/nyx_auto_registry.go` source that publishes a
/// `NyxAutoReceivers` map keyed by the target class name to a
/// zero-constructed instance.  The generated file lives in package
/// `entry` so it can reference `class` by bare identifier without
/// re-exporting through the harness package.  Compile-time enforcement
/// of the contract is delegated to the Go compiler — if the entry
/// package does not declare `class`, the build fails with a clear
/// `undefined: <class>` error.
fn generate_auto_receiver_registry(class: &str) -> String {
    format!(
        r##"// Code generated by Nyx — DO NOT EDIT.
package entry

// NyxAutoReceivers maps a class name to a zero-constructed instance
// the dynamic harness uses to reflect on methods at runtime.
var NyxAutoReceivers = map[string]interface{{}}{{
	"{class}": {class}{{}},
}}
"##,
        class = class,
    )
}

/// Phase 20 (Track M.2) — message-handler harness for Go.
///
/// The entry package is expected to declare a top-level handler
/// function named `spec.entry_name` taking either a `*entry.NyxPubsubMessage`
/// / `*entry.NyxNatsMsg` envelope or a `string` payload.  The harness
/// mounts the broker loopback declared by [`broker_pubsub`] /
/// [`broker_nats`], subscribes the handler reflectively, and publishes
/// the payload.  Broker pick is derived from
/// `spec.framework.adapter`: `pubsub-go` → Pub/Sub, `nats-go` → NATS,
/// default → Pub/Sub.
fn emit_message_handler_harness(spec: &HarnessSpec, queue: &str) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod_for_spec(GoShape::Generic, spec);
    let handler = &spec.entry_name;
    let broker = go_broker_for_adapter(spec);

    let (broker_src, publish_marker, dispatch) = match broker {
        GoBroker::Nats => (
            crate::dynamic::stubs::nats_source(crate::symbol::Lang::Go),
            crate::dynamic::stubs::NATS_PUBLISH_MARKER,
            format!(
                r##"	broker := NewNyxNatsLoopback()
	broker.Subscribe("{queue}", func(msg *NyxNatsMsg) {{
		nyxRecordBrokerEvent("NYX_NATS_LOG", "deliver", "{queue}", string(msg.Data))
		nyxDispatch(msg)
		nyxRecordBrokerEvent("NYX_NATS_LOG", "ack", "{queue}", msg.Subject)
	}})
	fmt.Println("{publish_marker} " + "{queue}")
	nyxRecordBrokerPublish("NYX_NATS_LOG", "{queue}", payload)
	broker.Publish("{queue}", payload)"##,
                queue = queue,
                publish_marker = crate::dynamic::stubs::NATS_PUBLISH_MARKER,
            ),
        ),
        GoBroker::Pubsub => (
            crate::dynamic::stubs::pubsub_source(crate::symbol::Lang::Go),
            crate::dynamic::stubs::PUBSUB_PUBLISH_MARKER,
            format!(
                r##"	broker := NewNyxPubsubLoopback()
	broker.Subscribe("{queue}", func(msg *NyxPubsubMessage) {{
		nyxRecordBrokerEvent("NYX_PUBSUB_LOG", "deliver", "{queue}", string(msg.Data))
		nyxDispatch(msg)
		msg.Ack()
		nyxRecordBrokerEvent("NYX_PUBSUB_LOG", "ack", "{queue}", msg.ID)
	}})
	fmt.Println("{publish_marker} " + "{queue}")
	nyxRecordBrokerPublish("NYX_PUBSUB_LOG", "{queue}", payload)
	broker.Publish("{queue}", payload)"##,
                queue = queue,
                publish_marker = crate::dynamic::stubs::PUBSUB_PUBLISH_MARKER,
            ),
        ),
    };

    // The handler is looked up reflectively through a per-package
    // `NyxHandlers` registry the entry file publishes (mirrors the
    // Phase 19 `NyxReceivers` contract).  A fallback path probes a few
    // common exported names so a fixture without the registry still
    // wires up.
    let dispatch_inner = format!(
        r##"func nyxDispatch(msg interface{{}}) {{
	defer func() {{
		if r := recover(); r != nil {{
			fmt.Fprintf(os.Stderr, "NYX_EXCEPTION: panic: %v\n", r)
		}}
	}}()
	fmt.Println("__NYX_SINK_HIT__")
	cb, ok := entry.NyxHandlers["{handler}"]
	if !ok {{
		fmt.Fprintln(os.Stderr, "NYX_HANDLER_NOT_FOUND: " + "{handler}")
		os.Exit(78)
	}}
	v := reflect.ValueOf(cb)
	args := make([]reflect.Value, v.Type().NumIn())
	for i := 0; i < v.Type().NumIn(); i++ {{
		want := v.Type().In(i)
		got := reflect.ValueOf(msg)
		if got.Type().AssignableTo(want) {{
			args[i] = got
		}} else if want.Kind() == reflect.String {{
			args[i] = reflect.ValueOf(nyxPayload())
		}} else {{
			args[i] = reflect.Zero(want)
		}}
	}}
	v.Call(args)
}}
"##,
        handler = handler,
    );

    let source = format!(
        r##"// Nyx dynamic harness — message handler (Phase 20 / Track M.2).
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"nyx-harness/entry"
)

{shim}

{broker_src}

{dispatch_inner}

func nyxPayload() string {{
	if v := os.Getenv("NYX_PAYLOAD"); v != "" {{
		return v
	}}
	if b64 := os.Getenv("NYX_PAYLOAD_B64"); b64 != "" {{
		if data, err := base64.StdEncoding.DecodeString(b64); err == nil {{
			return string(data)
		}}
	}}
	return ""
}}

func nyxRecordBrokerEvent(envName string, action string, destination string, payload string) {{
	path := os.Getenv(envName)
	if path == "" {{
		return
	}}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {{
		return
	}}
	defer f.Close()
	_, _ = fmt.Fprintf(
		f,
		"%s\t%s\t%s\n",
		strings.ReplaceAll(action, "\t", " "),
		strings.ReplaceAll(destination, "\t", " "),
		payload,
	)
}}

func nyxRecordBrokerPublish(envName string, destination string, payload string) {{
	nyxRecordBrokerEvent(envName, "publish", destination, payload)
}}

func main() {{
	__nyx_install_crash_guard("{handler}")
	payload := nyxPayload()
{dispatch}
}}
"##,
        broker_src = broker_src,
        dispatch_inner = dispatch_inner,
        dispatch = dispatch,
        handler = handler,
    );
    let _ = publish_marker;

    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files: vec![("go.mod".to_owned(), go_mod)],
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

// ── Phase 21 (Track M.3) — synthetic entry-kind harnesses ─────────────────────

/// Phase 21 (Track M.3) — GraphQL resolver harness for Go (gqlgen).
///
/// Looks up the named resolver via the entry package's `NyxResolvers`
/// map (mirrors the `NyxReceivers` / `NyxHandlers` contracts from
/// Phase 19 / 20), constructs a synthetic `context.Background()`, and
/// invokes the resolver with the payload positionally.
fn emit_graphql_resolver_harness(
    spec: &HarnessSpec,
    handler: &str,
    type_name: &str,
    field: &str,
) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod_for_spec(GoShape::Generic, spec);
    let source = format!(
        r##"// Nyx dynamic harness — GraphQL resolver (Phase 21 / Track M.3).
package main

import (
	"context"
	"fmt"
	"os"
	"reflect"

	"nyx-harness/entry"
)

{shim}

func nyxPayload() string {{
	if v := os.Getenv("NYX_PAYLOAD"); v != "" {{
		return v
	}}
	return ""
}}

func main() {{
	__nyx_install_crash_guard("{type_name}.{field}")
	payload := nyxPayload()
	fmt.Println("__NYX_GRAPHQL_RESOLVER__: " + "{type_name}" + "." + "{field}")
	fmt.Println("__NYX_SINK_HIT__")
	cb, ok := entry.NyxResolvers["{handler}"]
	if !ok {{
		fmt.Fprintln(os.Stderr, "NYX_RESOLVER_NOT_FOUND: " + "{handler}")
		os.Exit(78)
	}}
	v := reflect.ValueOf(cb)
	args := make([]reflect.Value, v.Type().NumIn())
	for i := 0; i < v.Type().NumIn(); i++ {{
		want := v.Type().In(i)
		if want.Kind() == reflect.String {{
			args[i] = reflect.ValueOf(payload)
		}} else if want.String() == "context.Context" {{
			args[i] = reflect.ValueOf(context.Background())
		}} else {{
			args[i] = reflect.Zero(want)
		}}
	}}
	defer func() {{
		if r := recover(); r != nil {{
			fmt.Fprintf(os.Stderr, "NYX_EXCEPTION: panic: %v\n", r)
		}}
	}}()
	out := v.Call(args)
	if len(out) > 0 {{
		fmt.Println(out[0].Interface())
	}}
}}
"##,
        handler = handler,
        type_name = type_name,
        field = field,
    );
    HarnessSource {
        source,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files: vec![("go.mod".to_owned(), go_mod)],
        entry_subpath: Some("entry/entry.go".to_owned()),
    }
}

#[derive(Debug, Clone, Copy)]
enum GoBroker {
    Pubsub,
    Nats,
}

fn go_broker_for_adapter(spec: &HarnessSpec) -> GoBroker {
    let adapter = spec
        .framework
        .as_ref()
        .map(|b| b.adapter.as_str())
        .unwrap_or("");
    match adapter {
        "nats-go" => GoBroker::Nats,
        _ => GoBroker::Pubsub,
    }
}

/// Minimal `gin` stub package used by [`GoShape::GinHandler`] fixtures
/// so the toolchain can compile without a real gin dependency.
/// Exposes just enough surface (Context.Query, Context.JSON,
/// Context.String, NewContext) to support the per-shape harness call.
fn gin_stub_pkg() -> String {
    r#"// Phase 15 — minimal gin stub for harness build (not the real gin).
package gin

import (
	"fmt"
	"io"
	"net/http"
)

type Context struct {
	Writer  http.ResponseWriter
	Request *http.Request
}

func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{Writer: w, Request: r}
}

func (c *Context) Query(name string) string {
	if c.Request == nil {
		return ""
	}
	return c.Request.URL.Query().Get(name)
}

func (c *Context) PostForm(name string) string {
	if c.Request == nil {
		return ""
	}
	_ = c.Request.ParseForm()
	return c.Request.PostFormValue(name)
}

func (c *Context) GetRawData() ([]byte, error) {
	if c.Request == nil || c.Request.Body == nil {
		return []byte{}, nil
	}
	return io.ReadAll(c.Request.Body)
}

func (c *Context) JSON(code int, obj interface{}) {
	if c.Writer != nil {
		c.Writer.WriteHeader(code)
		fmt.Fprintf(c.Writer, "%v", obj)
	}
}

func (c *Context) String(code int, format string, values ...interface{}) {
	if c.Writer != nil {
		c.Writer.WriteHeader(code)
		fmt.Fprintf(c.Writer, format, values...)
	}
}

func (c *Context) Redirect(code int, location string) {
	if c.Writer != nil {
		c.Writer.Header().Set("Location", location)
		c.Writer.WriteHeader(code)
	}
}
"#
    .to_owned()
}

/// Capitalize the first character of a string (Go exported names must start uppercase).
pub fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "go0000000000001".into(),
            entry_file: "cmd/server/main.go".into(),
            entry_name: "handleRequest".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Go,
            toolchain_id: "go-stable".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "cmd/server/main.go".into(),
            sink_line: 20,
            spec_hash: "go0000000000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("nyx-harness/entry"));
        assert!(harness.source.contains("nyxPayload()"));
        assert!(harness.source.contains("entry.HandleRequest(payload)"));
        assert_eq!(harness.filename, "main.go");
        assert_eq!(harness.command, vec!["./nyx_harness"]);
    }

    #[test]
    fn emit_includes_go_mod_in_extra_files() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        let go_mod = harness.extra_files.iter().find(|(n, _)| n == "go.mod");
        assert!(go_mod.is_some(), "go.mod must be in extra_files");
        assert!(go_mod.unwrap().1.contains("module nyx-harness"));
    }

    #[test]
    fn emit_entry_subpath_is_entry_go() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("entry/entry.go".to_owned()));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("DB_USER".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("os.Setenv"));
        assert!(harness.source.contains("\"DB_USER\""));
    }

    #[test]
    fn emit_stdin_is_unsupported() {
        let spec = make_spec(PayloadSlot::Stdin);
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!GoEmitter.entry_kinds_supported().is_empty());
        assert!(
            GoEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::Function)
        );
        assert!(
            GoEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::HttpRoute)
        );
        assert!(
            GoEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::CliSubcommand)
        );
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = GoEmitter.entry_kind_hint(EntryKindTag::LibraryApi);
        assert!(hint.contains("LibraryApi"));
        assert!(hint.contains("Phase 15"));
    }

    #[test]
    fn capitalize_first_handles_lowercase() {
        assert_eq!(capitalize_first("handleRequest"), "HandleRequest");
        assert_eq!(capitalize_first("run"), "Run");
        assert_eq!(capitalize_first(""), "");
        assert_eq!(capitalize_first("A"), "A");
    }

    #[test]
    fn go_mod_has_correct_module() {
        let go_mod = generate_go_mod(GoShape::Generic);
        assert!(go_mod.contains("module nyx-harness"));
        assert!(go_mod.contains("go 1.21"));
    }

    // ── Phase 15: shape detection ────────────────────────────────────────────

    fn make_spec_with(kind: EntryKind, name: &str, entry_file: &str) -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.entry_kind = kind;
        s.entry_name = name.to_owned();
        s.entry_file = entry_file.to_owned();
        s
    }

    #[test]
    fn shape_detect_http_handler_func() {
        let src = "package entry\nimport \"net/http\"\nfunc Handle(w http.ResponseWriter, r *http.Request) {}";
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::HttpHandlerFunc);
    }

    #[test]
    fn shape_detect_gin_handler() {
        let src = "package entry\nimport \"nyx-harness/entry/gin\"\nfunc Handle(c *gin.Context) {}";
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::GinHandler);
    }

    #[test]
    fn shape_detect_gin_route() {
        let src =
            "package main\nimport \"github.com/gin-gonic/gin\"\nfunc Handle(c *gin.Context) {}";
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::GinRoute);
    }

    #[test]
    fn shape_detect_echo_route() {
        let src = "package main\nimport \"github.com/labstack/echo/v4\"\nfunc Handle(c echo.Context) error { return nil }";
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::EchoRoute);
    }

    #[test]
    fn shape_detect_fiber_route() {
        let src = "package main\nimport \"github.com/gofiber/fiber/v2\"\nfunc Handle(c *fiber.Ctx) error { return nil }";
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::FiberRoute);
    }

    #[test]
    fn shape_detect_chi_route() {
        let src = "package main\nimport \"github.com/go-chi/chi/v5\"\nfunc Handle(w http.ResponseWriter, r *http.Request) {}";
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::ChiRoute);
    }

    #[test]
    fn gin_route_emits_marker_in_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::GinRoute);
        assert!(
            src.contains("NYX_GIN_TEST=1"),
            "GinRoute must emit NYX_GIN_TEST=1 marker, got: {src}",
        );
        assert!(src.contains("gin.New()"));
        assert!(src.contains("r.GET(\"/run\", entry.Handle)"));
        assert!(src.contains("r.ServeHTTP(rw, req)"));
    }

    #[test]
    fn echo_route_emits_marker_in_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::EchoRoute);
        assert!(src.contains("NYX_ECHO_TEST=1"));
        assert!(src.contains("echo.New()"));
        assert!(src.contains("e.GET(\"/run\", entry.Handle)"));
        assert!(src.contains("e.ServeHTTP(rw, req)"));
    }

    #[test]
    fn fiber_route_emits_marker_in_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::FiberRoute);
        assert!(src.contains("NYX_FIBER_TEST=1"));
        assert!(src.contains("fiber.New()"));
        assert!(src.contains("app.Get(\"/run\", entry.Handle)"));
        assert!(src.contains("app.Test(req)"));
    }

    #[test]
    fn chi_route_emits_marker_in_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::ChiRoute);
        assert!(src.contains("NYX_CHI_TEST=1"));
        assert!(src.contains("chi.NewRouter()"));
        assert!(src.contains("r.Get(\"/run\", entry.Handle)"));
        assert!(src.contains("r.ServeHTTP(rw, req)"));
    }

    #[test]
    fn shape_detect_flag_parse_cli() {
        let src = "package entry\nimport \"flag\"\nfunc Run() { flag.Parse() }";
        let spec = make_spec_with(EntryKind::CliSubcommand, "Run", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::FlagParseCli);
    }

    #[test]
    fn shape_detect_fuzz_variadic() {
        let src = "package entry\nfunc FuzzHandle(data []byte) error { return nil }";
        let spec = make_spec_with(EntryKind::Function, "FuzzHandle", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::FuzzVariadic);
    }

    #[test]
    fn shape_detect_generic_fallback() {
        let src = "package entry\nfunc Login(payload string) {}";
        let spec = make_spec_with(EntryKind::Function, "Login", "entry.go");
        assert_eq!(GoShape::detect(&spec, src), GoShape::Generic);
    }

    #[test]
    fn http_shape_emits_httptest_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::HttpHandlerFunc);
        assert!(src.contains("httptest.NewRequest"));
        assert!(src.contains("httptest.NewRecorder"));
        assert!(src.contains("entry.Handle(rw, req)"));
    }

    #[test]
    fn gin_shape_emits_context_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::GinHandler);
        assert!(src.contains("gin.NewContext"));
        assert!(src.contains("entry.Handle(ctx)"));
    }

    #[test]
    fn cli_shape_emits_os_args_setup() {
        let mut spec = make_spec_with(EntryKind::CliSubcommand, "Run", "entry.go");
        spec.payload_slot = PayloadSlot::Argv(0);
        let src = generate_main_go(&spec, GoShape::FlagParseCli);
        assert!(src.contains("os.Args = []string"));
        assert!(src.contains("entry.Run()"));
    }

    #[test]
    fn fuzz_shape_emits_bytes_invocation() {
        let spec = make_spec_with(EntryKind::Function, "FuzzHandle", "entry.go");
        let src = generate_main_go(&spec, GoShape::FuzzVariadic);
        assert!(src.contains("entry.FuzzHandle([]byte(payload))"));
    }

    #[test]
    fn emit_splices_probe_shim_and_installs_crash_guard() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        assert!(
            h.source.contains("__nyx_probe shim (Phase 06 — Track C.1"),
            "probe_shim banner missing from generated main.go — splicing regressed",
        );
        assert!(
            h.source.contains("func __nyx_install_crash_guard("),
            "install_crash_guard definition missing from generated main.go",
        );
        assert!(
            h.source
                .contains("__nyx_install_crash_guard(\"HandleRequest\")"),
            "install_crash_guard call site missing or wrong callee in main()",
        );
        let install_pos = h
            .source
            .find("__nyx_install_crash_guard(\"HandleRequest\")")
            .unwrap();
        let payload_pos = h.source.find("payload := nyxPayload()").unwrap();
        let invoke_pos = h.source.find("entry.HandleRequest(payload)").unwrap();
        assert!(
            payload_pos < install_pos && install_pos < invoke_pos,
            "install_crash_guard ordering wrong: payload_pos={payload_pos} install_pos={install_pos} invoke_pos={invoke_pos}",
        );
    }

    #[test]
    fn emit_includes_shim_imports_in_import_block() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        for path in SHIM_IMPORTS {
            let quoted = format!("\"{path}\"");
            assert!(
                h.source.contains(&quoted),
                "expected shim-required import {quoted} in generated main.go",
            );
        }
    }

    #[test]
    fn probe_shim_publishes_stub_http_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("func __nyx_stub_http_record"),
            "Go probe shim must define __nyx_stub_http_record"
        );
        assert!(
            shim.contains("NYX_HTTP_LOG"),
            "stub recorder must read NYX_HTTP_LOG"
        );
    }

    #[test]
    fn probe_shim_publishes_stub_sql_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("func __nyx_stub_sql_record"),
            "Go probe shim must define __nyx_stub_sql_record"
        );
        assert!(
            shim.contains("NYX_SQL_LOG"),
            "stub recorder must read NYX_SQL_LOG"
        );
        assert!(
            shim.contains("strings.HasSuffix(query, \"\\n\")"),
            "Go SQL recorder must guarantee a trailing newline on the query line so SqlStub::drain_events frames each record"
        );
    }

    #[test]
    fn chain_step_splices_probe_shim_for_composite_reverify() {
        let step = chain_step(Some(b"<prev>"), None);
        assert!(
            step.source.contains("__nyx_probe"),
            "Go chain step must splice the probe shim"
        );
        assert!(
            step.source.starts_with("package main"),
            "Go chain step must open with package main"
        );
        assert!(
            step.source.contains("os.Getenv(\"NYX_PREV_OUTPUT\")"),
            "Go chain step must keep its NYX_PREV_OUTPUT forwarder"
        );
        let import_close = step.source.find(")\n").expect("import block must close");
        let shim_pos = step.source.find("__nyx_probe").unwrap();
        let main_pos = step.source.find("func main()").unwrap();
        assert!(
            import_close < shim_pos,
            "probe shim must come after the import block",
        );
        assert!(
            shim_pos < main_pos,
            "probe shim must come before func main() so its helpers are in scope when a sink rewrite splices in",
        );
        for path in SHIM_IMPORTS {
            let quoted = format!("\"{path}\"");
            assert!(
                step.source.contains(&quoted),
                "Go chain step must merge shim-required import {quoted} into its import block",
            );
        }
        // Driver imports preserved alongside the shim imports.
        assert!(step.source.contains("\"fmt\""));
        assert!(step.source.contains("\"os\""));
    }

    // ── Phase 08 / 09 tier-(a) helpers + emitters ───────────────────────────

    #[test]
    fn rewrite_package_replaces_first_package_line() {
        let src = "// header\npackage vuln\n\nimport \"net/http\"\n\nfunc Run() {}\n";
        let out = rewrite_package(src, "vulnentry");
        assert!(
            out.contains("\npackage vulnentry\n"),
            "rewrite must produce `package vulnentry`, got:\n{out}",
        );
        assert!(
            !out.contains("\npackage vuln\n"),
            "original `package vuln` must be gone after rewrite, got:\n{out}",
        );
        // Other lines preserved verbatim.
        assert!(out.contains("// header"));
        assert!(out.contains("import \"net/http\""));
        assert!(out.contains("func Run() {}"));
    }

    #[test]
    fn rewrite_package_handles_crlf_line_endings() {
        let src = "package benign\r\nimport \"net/http\"\r\n";
        let out = rewrite_package(src, "vulnentry");
        assert!(out.starts_with("package vulnentry\r\n"));
        assert!(out.contains("import \"net/http\""));
    }

    #[test]
    fn rewrite_package_passes_through_when_no_package_line() {
        let src = "// no package decl here\nimport \"net/http\"\n";
        let out = rewrite_package(src, "vulnentry");
        assert_eq!(out, src);
    }

    #[test]
    fn header_injection_tier_a_fires_when_net_http_imported() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "Run".into();
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = "tests/dynamic_fixtures/header_injection/go/vuln.go".into();
        let harness = emit_header_injection_harness(&spec);
        assert!(
            harness.source.contains("nyx-harness/internal/vulnentry"),
            "tier-(a) header_injection must import the rewritten fixture package",
        );
        assert!(
            harness.source.contains("nyxHeaderViaFixture(payload)"),
            "tier-(a) header_injection must dispatch via fixture wrapper",
        );
        assert!(
            harness.source.contains("vulnentry.Run(rec, payload)"),
            "tier-(a) header_injection must call <entry>.Run(rec, payload)",
        );
        assert!(
            harness.source.contains("rec.Header()"),
            "tier-(a) header_injection must walk rec.Header() for captured headers",
        );
        // Rewritten fixture must be staged under internal/vulnentry/.
        let staged = harness
            .extra_files
            .iter()
            .find(|(p, _)| p == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_some(),
            "tier-(a) header_injection must stage internal/vulnentry/vulnentry.go",
        );
        assert!(
            staged.unwrap().1.contains("package vulnentry"),
            "staged fixture must carry the rewritten package declaration",
        );
    }

    #[test]
    fn header_injection_tier_b_falls_back_when_no_net_http() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "Run".into();
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = "/nonexistent/missing.go".into();
        let harness = emit_header_injection_harness(&spec);
        assert!(
            !harness.source.contains("nyx-harness/internal/vulnentry"),
            "tier-(b) header_injection must not import a fixture package",
        );
        assert!(
            harness
                .source
                .contains("nyxHeaderProbe(\"Set-Cookie\", payload)"),
            "tier-(b) header_injection must emit synthetic Set-Cookie probe",
        );
        assert!(
            harness
                .extra_files
                .iter()
                .all(|(p, _)| p != "internal/vulnentry/vulnentry.go"),
            "tier-(b) header_injection must not stage a rewritten fixture",
        );
    }

    #[test]
    fn open_redirect_tier_a_fires_when_gin_imported() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "Run".into();
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = "tests/dynamic_fixtures/open_redirect/go/vuln.go".into();
        let harness = emit_open_redirect_harness(&spec);
        assert!(
            harness.source.contains("nyx-harness/internal/vulnentry"),
            "tier-(a) open_redirect must import the rewritten fixture package",
        );
        assert!(
            harness
                .source
                .contains("nyx-harness/internal/vulnentry/gin"),
            "tier-(a) open_redirect must import the local gin stub",
        );
        assert!(
            harness.source.contains("nyxRedirectViaFixture(payload)"),
            "tier-(a) open_redirect must dispatch via fixture wrapper",
        );
        assert!(
            harness.source.contains("vulnentry.Run(ctx, payload)"),
            "tier-(a) open_redirect must call <entry>.Run(ctx, payload)",
        );
        assert!(
            harness.source.contains("rec.Header().Get(\"Location\")"),
            "tier-(a) open_redirect must read Location off the recorder",
        );
        let staged_fixture = harness
            .extra_files
            .iter()
            .find(|(p, _)| p == "internal/vulnentry/vulnentry.go");
        assert!(
            staged_fixture.is_some(),
            "tier-(a) open_redirect must stage internal/vulnentry/vulnentry.go",
        );
        let staged_fixture = staged_fixture.unwrap();
        assert!(
            staged_fixture.1.contains("package vulnentry"),
            "staged fixture must carry the rewritten package",
        );
        assert!(
            staged_fixture
                .1
                .contains("\"nyx-harness/internal/vulnentry/gin\""),
            "staged fixture must have its gin import rewritten to the local stub",
        );
        let staged_gin = harness
            .extra_files
            .iter()
            .find(|(p, _)| p == "internal/vulnentry/gin/gin.go");
        assert!(
            staged_gin.is_some(),
            "tier-(a) open_redirect must stage the gin stub",
        );
        assert!(
            staged_gin
                .unwrap()
                .1
                .contains("func (c *Context) Redirect("),
            "staged gin stub must expose Redirect",
        );
    }

    #[test]
    fn open_redirect_tier_b_falls_back_when_no_framework() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "Run".into();
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = "/nonexistent/missing.go".into();
        let harness = emit_open_redirect_harness(&spec);
        assert!(
            !harness.source.contains("nyx-harness/internal/vulnentry"),
            "tier-(b) open_redirect must not import a fixture package",
        );
        assert!(
            harness
                .source
                .contains("nyxRedirectProbe(payload, requestHost)"),
            "tier-(b) open_redirect must emit synthetic redirect probe",
        );
        assert!(
            harness
                .extra_files
                .iter()
                .all(|(p, _)| !p.starts_with("internal/vulnentry/")),
            "tier-(b) open_redirect must not stage any rewritten fixture or stub",
        );
    }

    #[test]
    fn emit_open_redirect_harness_ships_follow_location_helper() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "Run".into();
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = "/nonexistent/missing.go".into();
        let harness = emit_open_redirect_harness(&spec);
        assert!(
            harness
                .source
                .contains("func nyxFollowLocation(location string)"),
            "OPEN_REDIRECT harness must declare the nyxFollowLocation helper",
        );
        assert!(
            harness
                .source
                .contains("strings.HasPrefix(location, \"http://127.0.0.1\")"),
            "follower must gate on loopback 127.0.0.1 host prefix",
        );
        assert!(
            harness
                .source
                .contains("strings.HasPrefix(location, \"http://localhost\")"),
            "follower must gate on loopback localhost host prefix",
        );
        assert!(
            harness
                .source
                .contains("strings.HasPrefix(location, \"http://host-gateway\")"),
            "follower must gate on loopback host-gateway prefix",
        );
        assert!(
            harness.source.contains("client.Get(location)"),
            "follower must drive a real http.Client.Get against the captured Location",
        );
        // Tier-(b) callsite must call the follower on the synthetic payload.
        assert!(
            harness
                .source
                .contains("nyxRedirectProbe(payload, requestHost)\n\tnyxFollowLocation(payload)"),
            "tier-(b) callsite must invoke nyxFollowLocation after the synthetic probe",
        );
        // Even tier-(b) must pull in net/http so the follower compiles.
        assert!(
            harness.source.contains("\"net/http\""),
            "OPEN_REDIRECT harness must always import net/http so nyxFollowLocation compiles",
        );
    }

    #[test]
    fn emit_open_redirect_harness_follows_captured_location_in_tier_a() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_name = "Run".into();
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = "tests/dynamic_fixtures/open_redirect/go/vuln.go".into();
        let harness = emit_open_redirect_harness(&spec);
        // Tier-(a) gin: when fixture call succeeds, follow the captured loc.
        assert!(
            harness
                .source
                .contains("nyxRedirectProbe(loc, requestHost)\n\t\tnyxFollowLocation(loc)"),
            "tier-(a) callsite must invoke nyxFollowLocation on the captured Location",
        );
        // Tier-(a) fixture-call-failed branch falls back to payload-as-loc.
        assert!(
            harness
                .source
                .contains("nyxRedirectProbe(payload, requestHost)\n\t\tnyxFollowLocation(payload)"),
            "tier-(a) fixture-failure branch must still follow the synthetic payload",
        );
    }

    #[test]
    fn gin_stub_pkg_exposes_redirect_method() {
        let stub = gin_stub_pkg();
        assert!(
            stub.contains("func (c *Context) Redirect(code int, location string)"),
            "gin stub must expose a Redirect method tier-(a) open_redirect drives the fixture through",
        );
        // The Redirect method must set Location and write the status.
        assert!(stub.contains("c.Writer.Header().Set(\"Location\", location)"));
        assert!(stub.contains("c.Writer.WriteHeader(code)"));
    }

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
            "tests/dynamic_fixtures/crypto/go/vuln.go",
            "Run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyxWeakKeyProbe"),
            "dispatcher must short-circuit Cap::CRYPTO into emit_crypto_harness so the weak-key probe shim is present",
        );
        assert!(
            h.source.contains("\"kind\": \"WeakKey\""),
            "crypto harness must record probes with `kind: WeakKey` so the WeakKeyEntropy predicate fires",
        );
    }

    #[test]
    fn emit_crypto_harness_routes_through_internal_vulnentry_package() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/go/vuln.go",
            "Run",
        ));
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_some(),
            "tier-(a) crypto harness must stage the fixture under internal/vulnentry/ so main.go can import it",
        );
        let body = &staged.unwrap().1;
        assert!(
            body.contains("package vulnentry"),
            "fixture package name must be rewritten to vulnentry so the import path resolves",
        );
        assert!(
            h.source.contains("nyx-harness/internal/vulnentry"),
            "main.go must import the rewritten vulnentry package",
        );
        assert!(
            h.source.contains("vulnentry.Run(payload)"),
            "main.go must invoke the entry function on the rewritten fixture, not a synthetic stub",
        );
    }

    #[test]
    fn emit_crypto_harness_emits_weak_key_probe_kind() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/go/vuln.go",
            "Run",
        ));
        assert!(
            h.source.contains("\"kind\": \"WeakKey\", \"key_int\":"),
            "Go CRYPTO harness must emit ProbeKind::WeakKey records carrying a key_int field so the WeakKeyEntropy predicate fires",
        );
        assert!(
            h.source.contains("__NYX_SINK_HIT__"),
            "Go CRYPTO harness must print the universal sink-hit sentinel",
        );
    }

    #[test]
    fn emit_crypto_harness_reduces_byte_slice_returns_via_big_endian() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/go/benign.go",
            "Run",
        ));
        assert!(
            h.source.contains("binary.BigEndian.Uint64"),
            "Go CRYPTO harness must use binary.BigEndian.Uint64 so byte-slice returns reduce to a magnitude that exceeds the 16-bit budget on CSPRNG keys",
        );
        assert!(
            h.source.contains("reflect.ValueOf"),
            "Go CRYPTO harness must use reflect to dispatch on the produced key's type",
        );
        assert!(
            h.source.contains("case reflect.Slice"),
            "Go CRYPTO harness must handle the []byte branch from CSPRNG benign controls",
        );
    }

    #[test]
    fn emit_crypto_harness_falls_back_when_fixture_source_unavailable() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::CRYPTO;
        spec.entry_file = "/nonexistent/path/missing.go".into();
        spec.entry_name = "Run".into();
        let h = emit_crypto_harness(&spec);
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_none(),
            "fallback path must not stage a vulnentry copy when the fixture cannot be read",
        );
        assert!(
            !h.source.contains("nyx-harness/internal/vulnentry"),
            "fallback path must not import the missing vulnentry package",
        );
        assert!(
            h.source.contains("nyxWeakKeyProbe"),
            "fallback path must still emit a weak-key probe so the universal sink-hit path fires",
        );
    }

    // ── Phase 11 (Track J.9) Go JSON_PARSE emitter tests ──────────────────────

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
            "tests/dynamic_fixtures/json_parse_depth/go/vuln.go",
            "Run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyxJsonParseProbe"),
            "dispatcher must short-circuit Cap::JSON_PARSE into emit_json_parse_harness so the depth probe shim is present",
        );
        assert!(
            h.source.contains("\"kind\":            \"JsonParse\","),
            "JSON_PARSE harness must record probes with kind JsonParse",
        );
    }

    #[test]
    fn emit_json_parse_harness_routes_through_internal_vulnentry_package() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/go/vuln.go",
            "Run",
        ));
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_some(),
            "tier-(a) JSON_PARSE harness must stage the fixture under internal/vulnentry/",
        );
        assert!(
            staged.unwrap().1.contains("package vulnentry"),
            "fixture package name must be rewritten to vulnentry",
        );
        assert!(
            h.source.contains("nyx-harness/internal/vulnentry"),
            "main.go must import the rewritten vulnentry package",
        );
        assert!(
            h.source.contains("vulnentry.Run(payload)"),
            "main.go must invoke the entry function on the rewritten fixture",
        );
    }

    #[test]
    fn emit_json_parse_harness_emits_depth_fields() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/go/vuln.go",
            "Run",
        ));
        assert!(h.source.contains("\"depth\":           depth"));
        assert!(h.source.contains("\"excessive_depth\": excessive"));
        assert!(h.source.contains("depth > 64"));
        assert!(h.source.contains("__NYX_SINK_HIT__"));
    }

    #[test]
    fn emit_json_parse_harness_uses_iterative_walker() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/go/vuln.go",
            "Run",
        ));
        assert!(
            h.source.contains("func nyxJsonCountDepth"),
            "Go JSON_PARSE harness must define the iterative depth walker",
        );
        assert!(
            h.source.contains("map[string]interface{}:"),
            "depth walker must dispatch on the JSON object type",
        );
        assert!(
            h.source.contains("[]interface{}:"),
            "depth walker must dispatch on the JSON array type",
        );
    }

    #[test]
    fn emit_json_parse_harness_falls_back_when_fixture_source_unavailable() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::JSON_PARSE;
        spec.entry_file = "/nonexistent/path/missing.go".into();
        spec.entry_name = "Run".into();
        let h = emit_json_parse_harness(&spec);
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_none(),
            "fallback path must not stage a vulnentry copy when the fixture cannot be read",
        );
        assert!(
            !h.source.contains("nyx-harness/internal/vulnentry"),
            "fallback path must not import the missing vulnentry package",
        );
        assert!(
            h.source.contains("nyxJsonParseProbe"),
            "fallback path must still emit a JSON_PARSE probe so the universal sink-hit path fires",
        );
    }

    // ── Phase 11 (Track J.9) Go UNAUTHORIZED_ID emitter tests ──────────────────

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
            "tests/dynamic_fixtures/unauthorized_id/go/vuln.go",
            "Run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyxIdorAccessProbe"),
            "dispatcher must short-circuit Cap::UNAUTHORIZED_ID into emit_unauthorized_id_harness so the IDOR probe shim is present",
        );
        assert!(
            h.source.contains("\"kind\":      \"IdorAccess\""),
            "Go UNAUTHORIZED_ID harness must record probes with kind IdorAccess so IdorBoundaryCrossed fires",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_pins_caller_id() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/go/vuln.go",
            "Run",
        ));
        assert!(
            h.source.contains("const _NYX_CALLER_ID = \"alice\""),
            "Go UNAUTHORIZED_ID harness must pin caller_id to \"alice\"",
        );
        assert!(
            h.source
                .contains("nyxIdorAccessProbe(_NYX_CALLER_ID, payload)"),
            "Go UNAUTHORIZED_ID harness must call probe with caller_id + payload-as-owner",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_gates_probe_on_record_presence() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/go/benign.go",
            "Run",
        ));
        assert!(
            h.source
                .contains("if nyxUnauthorizedIdViaFixture(payload) {"),
            "Go UNAUTHORIZED_ID harness must gate probe emission on a present record so the benign fixture's empty-string rejection clears the predicate",
        );
        assert!(
            h.source.contains("func nyxRecordPresent("),
            "Go UNAUTHORIZED_ID harness must define a reflect-driven presence check that handles string / pointer / map / interface returns",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_routes_through_internal_vulnentry_package() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/go/vuln.go",
            "Run",
        ));
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_some(),
            "tier-(a) UNAUTHORIZED_ID harness must stage the fixture under internal/vulnentry/ so main.go can import it",
        );
        let body = &staged.unwrap().1;
        assert!(
            body.contains("package vulnentry"),
            "fixture package name must be rewritten to vulnentry so the import path resolves",
        );
        assert!(
            h.source.contains("nyx-harness/internal/vulnentry"),
            "main.go must import the rewritten vulnentry package",
        );
        assert!(
            h.source.contains("vulnentry.Run(payload)"),
            "main.go must invoke the entry function on the rewritten fixture",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_falls_back_when_fixture_source_unavailable() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::UNAUTHORIZED_ID;
        spec.entry_file = "/nonexistent/path/missing.go".into();
        spec.entry_name = "Run".into();
        let h = emit_unauthorized_id_harness(&spec);
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_none(),
            "fallback path must not stage a vulnentry copy when the fixture cannot be read",
        );
        assert!(
            h.source
                .contains("nyxIdorAccessProbe(_NYX_CALLER_ID, payload)"),
            "fallback path must still emit an IDOR probe so the universal sink-hit path fires",
        );
    }

    // ── Phase 11 (Track J.9) Go DATA_EXFIL emitter tests ───────────────────────

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
            "tests/dynamic_fixtures/data_exfil/go/vuln.go",
            "Run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyxOutboundProbe"),
            "dispatcher must short-circuit Cap::DATA_EXFIL into emit_data_exfil_harness so the outbound probe shim is present",
        );
        assert!(
            h.source.contains("\"kind\": \"OutboundNetwork\""),
            "Go DATA_EXFIL harness must record probes with kind OutboundNetwork so OutboundHostNotIn fires",
        );
    }

    #[test]
    fn emit_data_exfil_harness_overrides_default_transport() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/go/vuln.go",
            "Run",
        ));
        assert!(
            h.source.contains("type nyxRoundTripper struct{}"),
            "Go DATA_EXFIL harness must define the nyxRoundTripper interceptor type",
        );
        assert!(
            h.source.contains("http.DefaultTransport = rt"),
            "Go DATA_EXFIL harness must override http.DefaultTransport so package-level http.Get routes through the interceptor",
        );
        assert!(
            h.source
                .contains("http.DefaultClient = &http.Client{Transport: rt}"),
            "Go DATA_EXFIL harness must override http.DefaultClient so consumers that call DefaultClient.Do also route through the interceptor",
        );
    }

    #[test]
    fn emit_data_exfil_harness_parses_host_via_url_hostname() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/go/vuln.go",
            "Run",
        ));
        assert!(
            h.source.contains("req.URL.Hostname()"),
            "Go DATA_EXFIL harness must extract host via req.URL.Hostname()",
        );
        assert!(
            h.source.contains("nyxOutboundProbe(host)"),
            "Go DATA_EXFIL harness must emit the outbound probe with the parsed host",
        );
    }

    #[test]
    fn emit_data_exfil_harness_installs_transport_before_fixture_call() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/go/vuln.go",
            "Run",
        ));
        let install_idx = h
            .source
            .find("nyxInstallHttpTransport()")
            .expect("install call present");
        let fixture_idx = h
            .source
            .find("nyxDataExfilViaFixture(payload)")
            .expect("fixture call present");
        assert!(
            install_idx < fixture_idx,
            "Go DATA_EXFIL harness must install the transport override before invoking the fixture so the first http.Get is intercepted",
        );
    }

    #[test]
    fn emit_data_exfil_harness_routes_through_internal_vulnentry_package() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/go/vuln.go",
            "Run",
        ));
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_some(),
            "tier-(a) DATA_EXFIL harness must stage the fixture under internal/vulnentry/ so main.go can import it",
        );
        let body = &staged.unwrap().1;
        assert!(
            body.contains("package vulnentry"),
            "fixture package name must be rewritten to vulnentry so the import path resolves",
        );
        assert!(
            h.source.contains("nyx-harness/internal/vulnentry"),
            "main.go must import the rewritten vulnentry package",
        );
        assert!(
            h.source.contains("vulnentry.Run(payload)"),
            "main.go must invoke the entry function on the rewritten fixture",
        );
    }

    #[test]
    fn emit_data_exfil_harness_falls_back_when_fixture_source_unavailable() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::DATA_EXFIL;
        spec.entry_file = "/nonexistent/path/missing.go".into();
        spec.entry_name = "Run".into();
        let h = emit_data_exfil_harness(&spec);
        let staged = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "internal/vulnentry/vulnentry.go");
        assert!(
            staged.is_none(),
            "fallback path must not stage a vulnentry copy when the fixture cannot be read",
        );
        assert!(
            h.source.contains("nyxOutboundProbe(payload)"),
            "fallback path must still emit an outbound probe so the universal sink-hit path fires",
        );
    }
}
