//! JavaScript / TypeScript harness emitter.
//!
//! Generates a Node.js script that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Requires the entry module from the workdir (`entry.js`).
//! 3. Calls the entry function with the payload routed to the correct slot.
//! 4. Catches all exceptions to prevent harness crashes from masking results.
//!
//! Sink-reachability probe: the fixture itself emits `__NYX_SINK_HIT__` before
//! the actual sink call (same pattern as Rust fixtures). The harness is a pure
//! runner with no line-level tracing.
//!
//! Payload slot support:
//! - `PayloadSlot::Param(n)` — n-th positional argument.
//! - `PayloadSlot::EnvVar(name)` — set env var before calling.
//! - `PayloadSlot::Stdin` — pipe payload to process.stdin.
//! - Other slots produce `UnsupportedReason::EntryKindUnsupported`.
//!
//! Build: no compilation step. Command is `node harness.js`.
//! Build container: `nyx-build-node:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::lang::HarnessSource;
use crate::dynamic::spec::{HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;

/// Emit a Node.js harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_) | PayloadSlot::EnvVar(_) | PayloadSlot::Stdin => {}
        _ => return Err(UnsupportedReason::EntryKindUnsupported),
    }

    let source = generate_source(spec);
    let entry_filename = entry_module_filename(&spec.entry_file);

    Ok(HarnessSource {
        source,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: vec![],
        entry_subpath: Some(entry_filename),
    })
}

fn generate_source(spec: &HarnessSpec) -> String {
    let entry_module = entry_module_name(&spec.entry_file);
    let entry_fn = &spec.entry_name;
    let (pre_call, call_expr) = build_call(spec, &entry_module, entry_fn);

    format!(
        r#"'use strict';
// Nyx dynamic harness — auto-generated, do not edit.

// ── Payload loading ────────────────────────────────────────────────────────────
const _nyx_payload = (() => {{
    if (process.env.NYX_PAYLOAD && process.env.NYX_PAYLOAD.length > 0) {{
        return process.env.NYX_PAYLOAD;
    }}
    if (process.env.NYX_PAYLOAD_B64 && process.env.NYX_PAYLOAD_B64.length > 0) {{
        return Buffer.from(process.env.NYX_PAYLOAD_B64, 'base64').toString('utf8');
    }}
    return '';
}})();

// ── Entry module import ────────────────────────────────────────────────────────
let _entry;
try {{
    _entry = require('./{entry_module}');
}} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
}}

const payload = _nyx_payload;

// ── Pre-call setup ─────────────────────────────────────────────────────────────
{pre_call}
// ── Call entry point ──────────────────────────────────────────────────────────
try {{
    const _result = {call_expr};
    if (_result !== undefined && _result !== null) {{
        if (_result && typeof _result.then === 'function') {{
            _result
                .then(r => {{ if (r != null) process.stdout.write(String(r) + '\n'); }})
                .catch(e => {{ process.stderr.write('NYX_EXCEPTION: ' + e.message + '\n'); }});
        }} else {{
            process.stdout.write(String(_result) + '\n');
        }}
    }}
}} catch (e) {{
    process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
}}
"#,
        entry_module = entry_module,
        pre_call = pre_call,
        call_expr = call_expr,
    )
}

/// Build `(pre_call_setup, call_expression)` for the chosen payload slot.
fn build_call(spec: &HarnessSpec, _module: &str, func: &str) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(idx) => {
            let pre = String::new();
            let call = if *idx == 0 {
                format!("_entry.{func}(payload)")
            } else {
                let pads = (0..*idx).map(|_| "''").collect::<Vec<_>>().join(", ");
                format!("_entry.{func}({pads}, payload)")
            };
            (pre, call)
        }
        PayloadSlot::EnvVar(name) => {
            let pre = format!("process.env[{name:?}] = payload;\n");
            let call = format!("_entry.{func}()");
            (pre, call)
        }
        PayloadSlot::Stdin => {
            // Synchronous stdin replacement via Buffer.
            let pre = format!(
                "const {{ Readable }} = require('stream');\n\
                 process.stdin = Readable.from([Buffer.from(payload, 'utf8')]);\n"
            );
            let call = format!("_entry.{func}()");
            (pre, call)
        }
        _ => {
            let pre = String::new();
            let call = format!("_entry.{func}(payload)");
            (pre, call)
        }
    }
}

/// Derive the JS module name from an entry file path.
///
/// `"src/handlers/login.js"` → `"login"` (basename without extension).
pub fn entry_module_name(entry_file: &str) -> String {
    let base = entry_file
        .rsplit('/')
        .next()
        .unwrap_or(entry_file)
        .rsplit('\\')
        .next()
        .unwrap_or(entry_file);
    // Strip known JS/TS extensions.
    for ext in &[".js", ".mjs", ".cjs", ".ts", ".mts"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem.to_owned();
        }
    }
    base.to_owned()
}

/// Derive the filename for `entry_subpath` from an entry file path.
///
/// Always returns `"entry.js"` — fixture files are copied here regardless of
/// their original name so the harness can always `require('./entry')`.
pub fn entry_module_filename(_entry_file: &str) -> String {
    "entry.js".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "js000000000001".into(),
            entry_file: "src/app.js".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::JavaScript,
            toolchain_id: "node-20".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/app.js".into(),
            sink_line: 15,
            spec_hash: "js000000000001".into(),
        }
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("NYX_PAYLOAD"));
        assert!(harness.source.contains("require"));
        assert!(harness.source.contains("login"));
        assert_eq!(harness.filename, "harness.js");
        assert_eq!(harness.command, vec!["node", "harness.js"]);
    }

    #[test]
    fn emit_param_index_0() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("_entry.login(payload)"));
    }

    #[test]
    fn emit_param_index_1() {
        let spec = make_spec(PayloadSlot::Param(1));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("_entry.login('', payload)"));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("DB_HOST".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("process.env[\"DB_HOST\"] = payload"));
    }

    #[test]
    fn emit_stdin_slot() {
        let spec = make_spec(PayloadSlot::Stdin);
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("Readable"));
        assert!(harness.source.contains("process.stdin"));
    }

    #[test]
    fn emit_http_body_is_unsupported() {
        let spec = make_spec(PayloadSlot::HttpBody);
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::EntryKindUnsupported);
    }

    #[test]
    fn emit_entry_subpath_is_entry_js() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("entry.js".to_owned()));
    }

    #[test]
    fn entry_module_name_strips_extensions() {
        assert_eq!(entry_module_name("src/handlers/login.js"), "login");
        assert_eq!(entry_module_name("app.ts"), "app");
        assert_eq!(entry_module_name("handler.mjs"), "handler");
        assert_eq!(entry_module_name("no_ext"), "no_ext");
    }
}
