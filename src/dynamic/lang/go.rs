//! Go harness emitter.
//!
//! Generates a Go `main` package that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Imports the entry package from `./entry/` and calls the entry function.
//! 3. Uses `runtime.Caller`-style wrapping in fixtures for sink-reachability
//!    probes (fixtures explicitly emit `__NYX_SINK_HIT__` before the sink).
//!
//! Build step: `prepare_go()` in `build_sandbox.rs` runs `go build -o nyx_harness .`
//! in the workdir. The harness command is updated to the compiled binary path.
//!
//! File layout in workdir:
//! ```text
//! main.go         ← harness entry point (generated)
//! go.mod          ← module definition (generated)
//! entry/
//!   entry.go      ← entry function (copied from project; must have `package entry`)
//! ```
//!
//! Payload slot support:
//! - `PayloadSlot::Param(0)` — pass payload as `string` first argument.
//! - `PayloadSlot::EnvVar(name)` — set env var before calling entry.
//! - Other slots produce `UnsupportedReason::PayloadSlotUnsupported`.
//!
//! Build container: `nyx-build-go:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for Go.  Method bodies delegate to the
/// existing free functions in this module.
pub struct GoEmitter;

/// Entry kinds the Go emitter currently understands.  Extended in Phase 15
/// (Track B Go vertical) to include `HttpRoute` (`net/http`, gin) and CLI
/// (`flag.Parse`) shapes.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

impl LangEmitter for GoEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "go emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — Track B will add net/http, gin, flag.Parse shapes in phase 15"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_go(env)
    }
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
        PayloadSlot::Param(0) | PayloadSlot::EnvVar(_) => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    let main_go = generate_main_go(spec);
    let go_mod = generate_go_mod();

    Ok(HarnessSource {
        source: main_go,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files: vec![("go.mod".to_owned(), go_mod)],
        entry_subpath: Some("entry/entry.go".to_owned()),
    })
}

fn generate_main_go(spec: &HarnessSpec) -> String {
    let entry_fn = capitalize_first(&spec.entry_name);
    let (pre_call, call_expr) = build_call(spec, &entry_fn);

    // Determine which imports are needed.
    let env_import = if matches!(&spec.payload_slot, PayloadSlot::EnvVar(_)) {
        ""
    } else {
        ""
    };
    let _ = env_import;

    format!(
        r#"// Nyx dynamic harness — auto-generated, do not edit.
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"nyx-harness/entry"
)

func main() {{
	payload := nyxPayload()
{pre_call}	{call_expr}
	_ = fmt.Sprintf("") // suppress unused import if call_expr uses fmt directly
	_ = os.Stderr       // suppress unused import
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
        pre_call = pre_call,
        call_expr = call_expr,
    )
}

fn generate_go_mod() -> String {
    "module nyx-harness\n\ngo 1.21\n".to_owned()
}

/// Build `(pre_call_setup, call_expression)` for the chosen payload slot.
fn build_call(spec: &HarnessSpec, entry_fn: &str) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(0) => {
            let pre = String::new();
            let call = format!("entry.{entry_fn}(payload)");
            (pre, call)
        }
        PayloadSlot::EnvVar(name) => {
            let pre = format!("\tos.Setenv({name:?}, payload)\n");
            let call = format!("entry.{entry_fn}()");
            (pre, call)
        }
        _ => {
            let pre = String::new();
            let call = format!("entry.{entry_fn}(payload)");
            (pre, call)
        }
    }
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
    fn emit_param_gt_0_is_unsupported() {
        let spec = make_spec(PayloadSlot::Param(1));
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
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
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = GoEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("phase 15"));
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
}
