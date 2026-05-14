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
use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
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
const SUPPORTED: &[EntryKind] = &[
    EntryKind::Function,
    EntryKind::HttpRoute,
    EntryKind::CliSubcommand,
];

impl LangEmitter for GoEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "go emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 15 shape dispatch"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_go(env)
    }
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
        let kind = spec.entry_kind;

        let has_http_handler = source.contains("http.ResponseWriter")
            && source.contains("*http.Request");
        let has_gin = source.contains("gin.Context") || source.contains("*gin.Context");
        let has_flag_parse = source.contains("flag.Parse()") || source.contains("flag.Parse(");
        let has_fuzz_signature = source.contains("[]byte")
            && (entry.starts_with("Fuzz") || source.contains("// nyx-shape: fuzz"));

        if has_gin {
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
        if kind == EntryKind::HttpRoute {
            return Self::HttpHandlerFunc;
        }
        if kind == EntryKind::CliSubcommand {
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
    r#"
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
"#
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

fn generate_main_go(spec: &HarnessSpec, shape: GoShape) -> String {
    let entry_fn = capitalize_first(&spec.entry_name);
    let pre_call = pre_call_setup(spec);
    let imports = imports_for_shape(shape);
    let invocation = invoke_for_shape(spec, shape, &entry_fn);

    format!(
        r#"// Nyx dynamic harness — auto-generated, do not edit (Phase 15 — GoShape::{shape:?}).
package main

import (
{imports})

func main() {{
	payload := nyxPayload()
	_ = payload
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
    )
}

fn imports_for_shape(shape: GoShape) -> &'static str {
    match shape {
        GoShape::Generic => {
            "\t\"encoding/base64\"\n\t\"os\"\n\n\t\"nyx-harness/entry\"\n"
        }
        GoShape::HttpHandlerFunc => {
            "\t\"encoding/base64\"\n\t\"net/http\"\n\t\"net/http/httptest\"\n\t\"os\"\n\t\"strings\"\n\n\t\"nyx-harness/entry\"\n"
        }
        GoShape::GinHandler => {
            "\t\"encoding/base64\"\n\t\"net/http\"\n\t\"net/http/httptest\"\n\t\"os\"\n\t\"strings\"\n\n\t\"nyx-harness/entry\"\n\t\"nyx-harness/entry/gin\"\n"
        }
        GoShape::FlagParseCli => {
            "\t\"encoding/base64\"\n\t\"os\"\n\n\t\"nyx-harness/entry\"\n"
        }
        GoShape::FuzzVariadic => {
            "\t\"encoding/base64\"\n\t\"os\"\n\n\t\"nyx-harness/entry\"\n"
        }
    }
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
    }
}

fn generate_go_mod() -> String {
    "module nyx-harness\n\ngo 1.21\n".to_owned()
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
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
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
        assert!(GoEmitter.entry_kinds_supported().contains(&EntryKind::Function));
        assert!(GoEmitter.entry_kinds_supported().contains(&EntryKind::HttpRoute));
        assert!(GoEmitter.entry_kinds_supported().contains(&EntryKind::CliSubcommand));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = GoEmitter.entry_kind_hint(EntryKind::LibraryApi);
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
}
