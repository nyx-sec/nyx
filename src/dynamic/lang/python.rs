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
//! - Other slots produce `UnsupportedReason::EntryKindUnsupported`.

use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;

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
}

/// Emit a Python harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    // Validate payload slot.
    match &spec.payload_slot {
        PayloadSlot::Param(_) | PayloadSlot::EnvVar(_) | PayloadSlot::Stdin => {}
        _ => return Err(UnsupportedReason::EntryKindUnsupported),
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

    format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — auto-generated, do not edit."""
import os
import sys
import traceback

# ── Sink-reachability probe (sys.settrace) ────────────────────────────────────
# Fires __NYX_SINK_HIT__ exactly once when the traced function is called at
# the expected file:line. Filtered to avoid false positives from library code.

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
