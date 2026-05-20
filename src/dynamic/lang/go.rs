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

        let has_http_handler = source.contains("http.ResponseWriter")
            && source.contains("*http.Request");
        let has_gin_import = source.contains("github.com/gin-gonic/gin")
            || source.contains("// nyx-shape: gin");
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
    let candidates = [PathBuf::from(entry_file), PathBuf::from(".").join(entry_file)];
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
    if !deps.is_empty() {
        body.push_str("\nrequire (\n");
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

    // Phase 19 (Track M.1): ClassMethod short-circuit.  Go has no
    // classes — the dispatcher treats `class` as a top-level struct
    // declared in the entry file and `method` as a method on its
    // value or pointer receiver.  The harness instantiates a zero
    // value (`var v entry.Class`) and invokes `v.Method(payload)` via
    // reflection so an unexported method on a pointer receiver still
    // dispatches.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method_harness(class, method));
    }

    let entry_source = read_entry_source(&spec.entry_file);
    let shape = GoShape::detect(spec, &entry_source);
    let main_go = generate_main_go(spec, shape);
    let go_mod = generate_go_mod();

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
/// Reads `NYX_PAYLOAD`, scans for `<!ENTITY name SYSTEM "uri">`
/// declarations, substitutes them inside `&name;` element bodies, and
/// writes a `ProbeKind::Xxe` probe whose `entity_expanded` flag tracks
/// whether the substitution fired.  Standalone `main.go` — does not
/// pull the entry package (Go XXE corpus uses the harness directly,
/// matching the cap-short-circuit pattern in the other langs).
pub fn emit_xxe_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod();
    let source = format!(
        r##"// Nyx dynamic harness — XXE encoding/xml.Decoder (Phase 05 / Track J.3).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

{shim}

var nyxDoctypeEntityRE = regexp.MustCompile(`<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>`)
var nyxEntityRefRE = regexp.MustCompile(`&(\w+);`)

func nyxXmlParse(payload string) (string, bool) {{
	entities := map[string]string{{}}
	for _, m := range nyxDoctypeEntityRE.FindAllStringSubmatch(payload, -1) {{
		entities[m[1]] = "<" + m[2] + ">"
	}}
	expanded := false
	rendered := nyxEntityRefRE.ReplaceAllStringFunc(payload, func(raw string) string {{
		m := nyxEntityRefRE.FindStringSubmatch(raw)
		if m == nil {{
			return raw
		}}
		if body, ok := entities[m[1]]; ok {{
			expanded = true
			return body
		}}
		return raw
	}})
	return rendered, expanded
}}

func nyxWriteXxeProbe(rendered string, expanded bool) {{
	__nyx_emit(map[string]interface{{}}{{
		"sink_callee":    "xml.Decoder.Decode",
		"args":           []map[string]interface{{}}{{{{"kind": "String", "value": rendered}}}},
		"captured_at_ns": uint64(time.Now().UnixNano()),
		"payload_id":     os.Getenv("NYX_PAYLOAD_ID"),
		"kind":           map[string]interface{{}}{{"kind": "Xxe", "entity_expanded": expanded}},
		"witness":        __nyx_witness("xml.Decoder.Decode", []string{{rendered}}),
	}})
}}

func main() {{
	__nyx_install_crash_guard("xml.Decoder.Decode")
	defer __nyx_recover_crash("xml.Decoder.Decode")()
	payload := os.Getenv("NYX_PAYLOAD")
	rendered, expanded := nyxXmlParse(payload)
	nyxWriteXxeProbe(rendered, expanded)
	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"render": rendered, "entity_expanded": expanded}})
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
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented `Header.Set`
/// shim that records the *unmodified* value bytes (including any
/// embedded `\r\n`) via a `ProbeKind::HeaderEmit` probe.  Mirrors
/// the synthetic-harness pattern used by Phase 05.
pub fn emit_header_injection_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod();
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
)

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
		"kind":           map[string]interface{{}}{{"kind": "HeaderEmit", "name": name, "value": value}},
		"witness":        __nyx_witness("http.ResponseWriter.Header.Set", []string{{name, value}}),
	}})
}}

func main() {{
	__nyx_install_crash_guard("http.ResponseWriter.Header.Set")
	defer __nyx_recover_crash("http.ResponseWriter.Header.Set")()
	payload := os.Getenv("NYX_PAYLOAD")
	name := "Set-Cookie"
	value := payload
	nyxHeaderProbe(name, value)
	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"name": name, "value": value}})
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

/// Phase 09 — Track J.7 open-redirect harness for Go (`gin.Context.Redirect`
/// / `http.Redirect`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented redirect shim
/// that records the bound `Location:` value plus the request's
/// origin host via a `ProbeKind::Redirect` probe.
pub fn emit_open_redirect_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod();
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
)

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

func main() {{
	__nyx_install_crash_guard("gin.Context.Redirect")
	defer __nyx_recover_crash("gin.Context.Redirect")()
	payload := os.Getenv("NYX_PAYLOAD")
	requestHost := "example.com"
	location := payload
	nyxRedirectProbe(location, requestHost)
	fmt.Println("__NYX_SINK_HIT__")
	body, _ := json.Marshal(map[string]interface{{}}{{"location": location, "request_host": requestHost}})
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
const SHIM_IMPORTS: &[&str] = &[
    "encoding/json",
    "os/signal",
    "strings",
    "syscall",
    "time",
];

fn imports_for_shape(shape: GoShape) -> String {
    let stdlib_base: &[&str] = &["encoding/base64", "os"];
    let shape_extras: &[&str] = match shape {
        GoShape::Generic | GoShape::FlagParseCli | GoShape::FuzzVariadic => &[],
        GoShape::HttpHandlerFunc => &["net/http", "net/http/httptest"],
        GoShape::GinHandler => &["net/http", "net/http/httptest"],
        // Phase 17 framework variants drive a `httptest.NewServer`
        // bootstrap so they need the full net/http surface.
        GoShape::GinRoute
        | GoShape::EchoRoute
        | GoShape::FiberRoute
        | GoShape::ChiRoute => &["fmt", "net/http", "net/http/httptest"],
    };
    let local_pkgs: &[&str] = match shape {
        GoShape::GinHandler => &["nyx-harness/entry", "nyx-harness/entry/gin"],
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
            let pads = (0..*n).map(|_| "\"\"".to_owned()).collect::<Vec<_>>().join(", ");
            if pads.is_empty() {
                format!("\tos.Args = []string{{\"nyx_harness\", payload}}\n")
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
        // Phase 17 framework dispatchers.  Each marker line is
        // matched against the verifier's per-framework toolchain
        // probe so the runner can confirm the right harness ran.
        // v1 invocation re-uses the HttpHandlerFunc-style
        // `httptest.NewRequest` + `httptest.NewRecorder` shape
        // because the synthetic entry.go ships a stdlib
        // `(w, r)` handler shim that mirrors the framework
        // handler's body.
        GoShape::GinRoute => framework_route_invocation(
            spec,
            "NYX_GIN_TEST=1",
            entry_fn,
            use_body,
            &query_param,
        ),
        GoShape::EchoRoute => framework_route_invocation(
            spec,
            "NYX_ECHO_TEST=1",
            entry_fn,
            use_body,
            &query_param,
        ),
        GoShape::FiberRoute => framework_route_invocation(
            spec,
            "NYX_FIBER_TEST=1",
            entry_fn,
            use_body,
            &query_param,
        ),
        GoShape::ChiRoute => framework_route_invocation(
            spec,
            "NYX_CHI_TEST=1",
            entry_fn,
            use_body,
            &query_param,
        ),
    }
}

fn framework_route_invocation(
    _spec: &HarnessSpec,
    marker: &str,
    entry_fn: &str,
    use_body: bool,
    query_param: &str,
) -> String {
    let req_setup = if use_body {
        "\treq := httptest.NewRequest(\"POST\", \"/\", strings.NewReader(payload))\n".to_owned()
    } else {
        format!(
            "\treq := httptest.NewRequest(\"GET\", \"/?{q}=\"+payload, strings.NewReader(\"\"))\n",
            q = query_param
        )
    };
    format!(
        "\tfmt.Println(\"{marker}\")\n{req_setup}\trw := httptest.NewRecorder()\n\tentry.{entry_fn}(rw, req)\n\t_ = http.StatusOK\n"
    )
}

fn generate_go_mod() -> String {
    "module nyx-harness\n\ngo 1.21\n".to_owned()
}

/// Phase 19 (Track M.1) — class-method harness for Go.
///
/// `class` is mapped to a struct type declared in `entry/entry.go`
/// and `method` to a method-on-receiver.  The harness uses reflection
/// to construct a zero value, then invokes the method with the
/// payload — supporting both value and pointer receivers.
fn emit_class_method_harness(class: &str, method: &str) -> HarnessSource {
    let shim = probe_shim();
    let go_mod = generate_go_mod();
    let source = format!(
        r##"// Nyx dynamic harness — class method (Phase 19 / Track M.1).
package main

import (
	"fmt"
	"os"
	"reflect"

	"nyx-harness/entry"
)

{shim}

func nyxBuildReceiver(structName string) (reflect.Value, error) {{
	// Look up the exported type by name on the entry package.  Go's
	// reflect API does not expose package-level reflection over types
	// directly, so the dispatcher uses the package's well-known
	// `NyxReceivers` registry the entry file is expected to publish.
	if r, ok := entry.NyxReceivers[structName]; ok {{
		return reflect.ValueOf(r), nil
	}}
	return reflect.Value{{}}, fmt.Errorf("class not found: %s", structName)
}}

func nyxPayload() string {{
	if v := os.Getenv("NYX_PAYLOAD"); v != "" {{
		return v
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
        extra_files: vec![("go.mod".to_owned(), go_mod)],
        entry_subpath: Some("entry/entry.go".to_owned()),
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
        assert!(GoEmitter.entry_kinds_supported().contains(&EntryKindTag::Function));
        assert!(GoEmitter.entry_kinds_supported().contains(&EntryKindTag::HttpRoute));
        assert!(GoEmitter.entry_kinds_supported().contains(&EntryKindTag::CliSubcommand));
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
        let go_mod = generate_go_mod();
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
        let src = "package main\nimport \"github.com/gin-gonic/gin\"\nfunc Handle(c *gin.Context) {}";
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
        assert!(src.contains("httptest.NewRequest"));
    }

    #[test]
    fn echo_route_emits_marker_in_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::EchoRoute);
        assert!(src.contains("NYX_ECHO_TEST=1"));
    }

    #[test]
    fn fiber_route_emits_marker_in_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::FiberRoute);
        assert!(src.contains("NYX_FIBER_TEST=1"));
    }

    #[test]
    fn chi_route_emits_marker_in_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "Handle", "entry.go");
        let src = generate_main_go(&spec, GoShape::ChiRoute);
        assert!(src.contains("NYX_CHI_TEST=1"));
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
            h.source.contains("__nyx_install_crash_guard(\"HandleRequest\")"),
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
}
