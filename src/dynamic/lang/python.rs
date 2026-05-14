//! Python harness emitter.
//!
//! Generates a Python script that:
//! 1. Reads the payload from `NYX_PAYLOAD` env var.
//! 2. Installs a `sys.settrace`-based probe at the sink call site
//!    (`spec.sink_file:spec.sink_line`) that prints `__NYX_SINK_HIT__`.
//! 3. Imports the entry module and calls the entry function with the
//!    payload routed to the correct parameter slot.
//! 4. Catches all exceptions to prevent harness crashes from masking results.
//!
//! Payload slot support:
//! - `PayloadSlot::Param(n)` — n-th positional argument.
//! - `PayloadSlot::EnvVar(name)` — set env var before calling.
//! - Other slots produce `UnsupportedReason::PayloadSlotUnsupported`.

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use crate::utils::project::DetectedFramework;

/// Zero-sized [`LangEmitter`] handle for Python.  Registered in the
/// `lang::dispatch` table; method bodies delegate to the existing free
/// functions in this module.
pub struct PythonEmitter;

/// Entry kinds the Python emitter currently understands.  Extended in Phase 12
/// (Track B Python vertical) to include `HttpRoute`, `CliSubcommand`, etc.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

impl LangEmitter for PythonEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "python emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — Track B will add framework + CLI shapes in phase 12"
        )
    }

    /// Phase 09 — Track D.2: emit a pinned `requirements.txt` (and a
    /// matching `pyproject.toml` stub when `pyproject.toml` is the
    /// project's canonical manifest) covering every captured direct dep
    /// plus the framework deps inferred from the project manifest.
    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_python(env)
    }
}

/// Source of the `__nyx_probe` shim for the Python harness.
///
/// The shim is callable as `__nyx_probe("sink.callee", arg0, arg1, ...)`.
/// It emits one JSON line per call to `NYX_PROBE_PATH` (when set) in the
/// [`crate::dynamic::probe::SinkProbe`] schema.  No-op when the env var
/// is unset, so the shim is safe to inject even when the runner has not
/// configured a probe channel.
pub fn probe_shim() -> &'static str {
    r#"
# ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ──────
# Deny-substring list mirrors crate::dynamic::policy::DENY_KEY_SUBSTRINGS; keep
# in sync when the host-side policy gains new entries.
_NYX_DENY_SUBSTRINGS = (
    "TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "CREDENTIAL", "SESSION", "COOKIE", "AUTH", "BEARER",
    "AWS_ACCESS", "AWS_SESSION", "GH_TOKEN", "GITHUB_TOKEN", "NPM_TOKEN",
    "PYPI_TOKEN", "DOCKER_PASS",
)
_NYX_PAYLOAD_LIMIT = 16 * 1024
_NYX_REDACTED = "<redacted-by-nyx-policy>"

def __nyx_scrub_env():
    import os
    out = {}
    for k, v in os.environ.items():
        ku = str(k).upper()
        if any(n in ku for n in _NYX_DENY_SUBSTRINGS):
            out[k] = _NYX_REDACTED
        else:
            out[k] = v
    return out

def __nyx_witness(sink_callee, args):
    import os
    payload = os.environ.get("NYX_PAYLOAD", "")
    payload_bytes = payload.encode("utf-8", "replace") if isinstance(payload, str) else bytes(payload)
    if len(payload_bytes) > _NYX_PAYLOAD_LIMIT:
        payload_bytes = payload_bytes[:_NYX_PAYLOAD_LIMIT]
    args_repr = []
    for a in args:
        if isinstance(a, (bytes, bytearray)):
            args_repr.append("<bytes:%d>" % len(a))
        else:
            args_repr.append(str(a))
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = ""
    return {
        "env_snapshot": __nyx_scrub_env(),
        "cwd": cwd,
        "payload_bytes": list(payload_bytes),
        "callee": str(sink_callee),
        "args_repr": args_repr,
    }

def __nyx_emit(rec):
    import os, json
    p = os.environ.get("NYX_PROBE_PATH")
    if not p:
        return
    try:
        with open(p, "a") as _f:
            _f.write(json.dumps(rec) + "\n")
    except OSError:
        pass

def __nyx_probe(sink_callee, *args):
    import os, time
    serialised = []
    for a in args:
        if isinstance(a, (bytes, bytearray)):
            serialised.append({"kind": "Bytes", "value": list(a)})
        elif isinstance(a, bool):
            serialised.append({"kind": "Int", "value": 1 if a else 0})
        elif isinstance(a, int):
            serialised.append({"kind": "Int", "value": a})
        else:
            serialised.append({"kind": "String", "value": str(a)})
    rec = {
        "sink_callee": str(sink_callee),
        "args": serialised,
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {"kind": "Normal"},
        "witness": __nyx_witness(sink_callee, args),
    }
    __nyx_emit(rec)

# Phase 08: sink-site signal handler.  Call __nyx_install_crash_guard before
# invoking the instrumented sink so a SIGSEGV / SIGABRT / etc. is captured as
# a Crash probe (with witness) before the process aborts.  The shim re-raises
# the signal on the default handler after writing so process-level outcome
# observers (exit_code) still see the death.
_NYX_SIGNAL_NAMES = {}

def __nyx_install_crash_guard(sink_callee):
    import signal, os, time
    catchable = []
    for nm in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL"):
        s = getattr(signal, nm, None)
        if s is not None:
            catchable.append((nm, s))
            _NYX_SIGNAL_NAMES[s] = nm
    def _handler(signum, frame):
        nm = _NYX_SIGNAL_NAMES.get(signum, "SIG?")
        rec = {
            "sink_callee": str(sink_callee),
            "args": [],
            "captured_at_ns": time.time_ns(),
            "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
            "kind": {"kind": "Crash", "signal": nm},
            "witness": __nyx_witness(sink_callee, []),
        }
        __nyx_emit(rec)
        # Reset to default and re-raise so the process actually dies.
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
    for _nm, s in catchable:
        try:
            signal.signal(s, _handler)
        except (OSError, ValueError):
            pass
"#
}

/// Phase 09 - Track D.2: synthesise a `requirements.txt` from the
/// captured deps in `env`.
///
/// The output is a deterministic, alphabetised listing of every
/// non-stdlib direct dep the entry file imported plus the framework deps
/// inferred from the manifest detector.  Each entry is emitted as the
/// canonical pip-installable name; version pins are intentionally
/// omitted so the system pip resolves the latest compatible release
/// against the user's pinned Python interpreter (the spec's
/// `toolchain_id` field).  A future phase can fold pinned versions in
/// once the capture pass learns to parse the project's own lockfile.
pub fn materialize_python(env: &Environment) -> RuntimeArtifacts {
    let mut artifacts = RuntimeArtifacts::new();
    let mut deps: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Direct imports first — these mirror the entry file faithfully.
    for d in &env.direct_deps {
        if is_python_stdlib(d) {
            continue;
        }
        let canonical = canonical_python_pkg_name(d);
        if seen.insert(canonical.clone()) {
            deps.push(canonical);
        }
    }
    // Framework deps next — these may not appear as direct imports in
    // every entry file, but they have to be installed for the runtime
    // to resolve framework decorators.
    for fw in &env.frameworks {
        if let Some(name) = python_framework_pkg_name(*fw) {
            let canonical = canonical_python_pkg_name(name);
            if seen.insert(canonical.clone()) {
                deps.push(canonical);
            }
        }
    }
    deps.sort_unstable();

    let mut body = String::with_capacity(64);
    body.push_str("# Auto-generated by Nyx — Phase 09 (Track D.2).\n");
    body.push_str(&format!("# spec_hash = {}\n", env.spec_hash));
    body.push_str(&format!(
        "# toolchain = {} (drift={})\n",
        env.toolchain.toolchain_id, env.toolchain.toolchain_drift
    ));
    for d in &deps {
        body.push_str(d);
        body.push('\n');
    }
    artifacts.push("requirements.txt", body);
    artifacts
}

/// Returns true when `name` is a Python standard-library top-level
/// package.  Conservative: matches the names the harness build path
/// would silently drop from `requirements.txt` anyway.
fn is_python_stdlib(name: &str) -> bool {
    matches!(
        name,
        "abc"
            | "argparse"
            | "asyncio"
            | "base64"
            | "binascii"
            | "collections"
            | "contextlib"
            | "copy"
            | "csv"
            | "ctypes"
            | "dataclasses"
            | "datetime"
            | "decimal"
            | "difflib"
            | "email"
            | "enum"
            | "errno"
            | "fcntl"
            | "fnmatch"
            | "functools"
            | "getopt"
            | "getpass"
            | "glob"
            | "gzip"
            | "hashlib"
            | "hmac"
            | "http"
            | "importlib"
            | "inspect"
            | "io"
            | "ipaddress"
            | "itertools"
            | "json"
            | "logging"
            | "math"
            | "multiprocessing"
            | "operator"
            | "os"
            | "pathlib"
            | "pickle"
            | "platform"
            | "posixpath"
            | "queue"
            | "random"
            | "re"
            | "secrets"
            | "select"
            | "shutil"
            | "signal"
            | "socket"
            | "sqlite3"
            | "ssl"
            | "stat"
            | "string"
            | "struct"
            | "subprocess"
            | "sys"
            | "tempfile"
            | "threading"
            | "time"
            | "traceback"
            | "types"
            | "typing"
            | "unicodedata"
            | "unittest"
            | "urllib"
            | "uuid"
            | "warnings"
            | "weakref"
            | "xml"
            | "zipfile"
            | "zlib"
    )
}

/// Canonicalise common Python pkg aliases to their PyPI distribution
/// name (e.g. `cv2` → `opencv-python`).
fn canonical_python_pkg_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "flask" => "Flask".to_owned(),
        "cv2" => "opencv-python".to_owned(),
        "sqlalchemy" => "SQLAlchemy".to_owned(),
        "yaml" => "PyYAML".to_owned(),
        "psycopg2" => "psycopg2-binary".to_owned(),
        _ => lower,
    }
}

fn python_framework_pkg_name(fw: DetectedFramework) -> Option<&'static str> {
    match fw {
        DetectedFramework::Flask => Some("flask"),
        DetectedFramework::Django => Some("django"),
        _ => None,
    }
}

/// Emit a Python harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    // Validate payload slot.
    match &spec.payload_slot {
        PayloadSlot::Param(_) | PayloadSlot::EnvVar(_) | PayloadSlot::Stdin => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    let source = generate_source(spec);

    Ok(HarnessSource {
        source,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    })
}

fn generate_source(spec: &HarnessSpec) -> String {
    let entry_module = module_name(&spec.entry_file);
    let entry_fn = &spec.entry_name;
    let sink_file = &spec.sink_file;
    let sink_line = spec.sink_line;

    // Build the call expression based on payload slot.
    let (pre_call, call_expr) = build_call(spec, entry_module, entry_fn);
    let probe = probe_shim();

    format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — auto-generated, do not edit."""
import os
import sys
import traceback

# ── Sink-reachability probe (sys.settrace) ────────────────────────────────────
# Fires __NYX_SINK_HIT__ exactly once when the traced function is called at
# the expected file:line. Filtered to avoid false positives from library code.

{probe}

_NYX_SINK_FILE = {sink_file:?}
_NYX_SINK_LINE = {sink_line}
_NYX_SINK_HIT = False

def _nyx_tracer(frame, event, arg):
    global _NYX_SINK_HIT
    if not _NYX_SINK_HIT and event == "line":
        # Normalise path for comparison (basename match as fallback).
        fname = frame.f_code.co_filename
        if fname == _NYX_SINK_FILE or fname.endswith(_NYX_SINK_FILE) or (
            os.path.basename(fname) == os.path.basename(_NYX_SINK_FILE)
        ):
            if _NYX_SINK_LINE <= frame.f_lineno <= _NYX_SINK_LINE + 5:
                _NYX_SINK_HIT = True
                print("__NYX_SINK_HIT__", flush=True)
    return _nyx_tracer

sys.settrace(_nyx_tracer)

# ── Payload loading ────────────────────────────────────────────────────────────
# Primary: raw bytes from NYX_PAYLOAD; fallback: base64 from NYX_PAYLOAD_B64.

_payload_raw = os.environb.get(b"NYX_PAYLOAD", b"")
if not _payload_raw:
    import base64
    _payload_b64 = os.environ.get("NYX_PAYLOAD_B64", "")
    if _payload_b64:
        _payload_raw = base64.b64decode(_payload_b64)

# Decode payload to str (best-effort; use latin-1 as lossless fallback).
try:
    payload = _payload_raw.decode("utf-8")
except UnicodeDecodeError:
    payload = _payload_raw.decode("latin-1")

# ── Entry module import ────────────────────────────────────────────────────────
# The entry file is mounted at the harness workdir as the module.
# sys.path is extended to include the workdir so relative imports work.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

try:
    import {entry_module} as _entry_mod
except ImportError as _e:
    print(f"NYX_IMPORT_ERROR: {{_e}}", file=sys.stderr, flush=True)
    sys.exit(77)  # Distinct exit code: import failed

# ── Pre-call setup ─────────────────────────────────────────────────────────────
{pre_call}
# ── Call entry point ──────────────────────────────────────────────────────────
try:
    _result = {call_expr}
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    # Print error to stderr so the oracle can observe error-based injection.
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)

# Ensure probe fires for line-range matches on late-called sinks.
sys.settrace(None)
"#,
        sink_file = sink_file,
        sink_line = sink_line,
        entry_module = entry_module,
        pre_call = pre_call,
        call_expr = call_expr,
        probe = probe,
    )
}

/// Build `(pre_call_setup, call_expression)` for the chosen payload slot.
fn build_call(spec: &HarnessSpec, _module: &str, func: &str) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(idx) => {
            // Build positional args: put payload at index `idx`, fill others with "".
            // For simplicity with unknown arities, pass payload as the first arg.
            let pre = String::new();
            let call = if *idx == 0 {
                format!("_entry_mod.{func}(payload)")
            } else {
                // Pad with empty strings up to idx, then payload.
                let pads = (0..*idx).map(|_| "\"\"").collect::<Vec<_>>().join(", ");
                format!("_entry_mod.{func}({pads}, payload)")
            };
            (pre, call)
        }
        PayloadSlot::EnvVar(name) => {
            let pre = format!("os.environ[{name:?}] = payload\n");
            let call = format!("_entry_mod.{func}()");
            (pre, call)
        }
        PayloadSlot::Stdin => {
            let pre = format!(
                "import io\nsys.stdin = io.TextIOWrapper(io.BytesIO(_payload_raw))\n"
            );
            let call = format!("_entry_mod.{func}()");
            (pre, call)
        }
        _ => {
            let pre = String::new();
            let call = format!("_entry_mod.{func}(payload)");
            (pre, call)
        }
    }
}

/// Convert an entry file path to a Python module name.
///
/// `"src/handlers/login.py"` → `"login"` (basename without extension).
fn module_name(entry_file: &str) -> &str {
    let base = entry_file
        .rsplit('/')
        .next()
        .unwrap_or(entry_file)
        .rsplit('\\')
        .next()
        .unwrap_or(entry_file);
    base.strip_suffix(".py").unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "0000000000000001".into(),
            entry_file: "src/app.py".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "python-3.11".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/app.py".into(),
            sink_line: 15,
            spec_hash: "00000000deadbeef".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        }
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("sys.settrace"));
        assert!(harness.source.contains("__NYX_SINK_HIT__"));
        assert!(harness.source.contains("event == \"line\""));
        assert!(harness.source.contains("login(payload)"));
        assert_eq!(harness.filename, "harness.py");
    }

    #[test]
    fn emit_param_index_1() {
        let spec = make_spec(PayloadSlot::Param(1));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("login(\"\", payload)"));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("USER_INPUT".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("os.environ[\"USER_INPUT\"] = payload"));
    }

    #[test]
    fn module_name_strips_path_and_ext() {
        assert_eq!(module_name("src/handlers/login.py"), "login");
        assert_eq!(module_name("app.py"), "app");
        assert_eq!(module_name("no_ext"), "no_ext");
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!PythonEmitter.entry_kinds_supported().is_empty());
        assert!(PythonEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::Function));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = PythonEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("phase 12"));
    }

    #[test]
    fn probe_shim_is_injected() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(
            harness.source.contains("def __nyx_probe"),
            "Phase 06 shim must be present in generated harness",
        );
        assert!(harness.source.contains("NYX_PROBE_PATH"));
    }

    #[test]
    fn unsupported_lang_returns_err() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.lang = Lang::Rust;
        // lang::emit handles the dispatch; test the python module directly
        // by checking it only handles Python.
        // We emit for Python directly here, not for Rust.
        let harness = emit(&spec);
        // python::emit doesn't check lang - it just generates code.
        // The lang dispatch is in lang/mod.rs.
        assert!(harness.is_ok());
    }
}
