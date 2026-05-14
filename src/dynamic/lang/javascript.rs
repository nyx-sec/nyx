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
//! - Other slots produce `UnsupportedReason::PayloadSlotUnsupported`.
//!
//! Build: no compilation step. Command is `node harness.js`.
//! Build container: `nyx-build-node:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use crate::utils::project::DetectedFramework;

/// Zero-sized [`LangEmitter`] handle for JavaScript / TypeScript (one
/// emitter, both langs share the same Node.js dispatch).  Method bodies
/// delegate to the existing free functions in this module.
pub struct JavaScriptEmitter;

/// Entry kinds the JS / TS emitter currently understands.  Extended in
/// Phase 13 (Track B JS + TS vertical) to include `HttpRoute` (Express /
/// Koa / Next), `CliSubcommand`, etc.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

impl LangEmitter for JavaScriptEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "javascript / typescript emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — Track B will add Express / Koa / Next shapes in phase 13"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_node(env)
    }
}

/// Phase 09 — Track D.2: emit a `package.json` covering every captured
/// dep plus the framework deps inferred from the manifest detector.
///
/// Versions default to `"*"` so npm resolves to a recent compatible
/// release.  Re-used by the TypeScript emitter.
pub fn materialize_node(env: &Environment) -> RuntimeArtifacts {
    let mut artifacts = RuntimeArtifacts::new();
    let mut deps: Vec<(String, &'static str)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for d in &env.direct_deps {
        if is_node_builtin(d) {
            continue;
        }
        if seen.insert(d.clone()) {
            deps.push((d.clone(), "*"));
        }
    }
    for fw in &env.frameworks {
        if let Some(name) = node_framework_pkg_name(*fw) {
            if seen.insert(name.to_owned()) {
                deps.push((name.to_owned(), "*"));
            }
        }
    }
    deps.sort_by(|a, b| a.0.cmp(&b.0));

    let mut body = String::with_capacity(128);
    body.push_str("{\n");
    body.push_str("  \"name\": \"nyx-harness\",\n");
    body.push_str("  \"version\": \"0.0.0\",\n");
    body.push_str("  \"private\": true,\n");
    body.push_str("  \"dependencies\": {\n");
    for (i, (name, ver)) in deps.iter().enumerate() {
        body.push_str("    \"");
        body.push_str(name);
        body.push_str("\": \"");
        body.push_str(ver);
        body.push('"');
        if i + 1 != deps.len() {
            body.push(',');
        }
        body.push('\n');
    }
    body.push_str("  }\n");
    body.push_str("}\n");
    artifacts.push("package.json", body);
    artifacts
}

fn is_node_builtin(name: &str) -> bool {
    matches!(
        name,
        "fs"
            | "path"
            | "http"
            | "https"
            | "url"
            | "crypto"
            | "stream"
            | "util"
            | "child_process"
            | "os"
            | "events"
            | "buffer"
            | "querystring"
            | "zlib"
            | "assert"
            | "process"
            | "net"
            | "tls"
            | "dns"
            | "readline"
            | "tty"
    )
}

fn node_framework_pkg_name(fw: DetectedFramework) -> Option<&'static str> {
    match fw {
        DetectedFramework::Express => Some("express"),
        DetectedFramework::Koa => Some("koa"),
        DetectedFramework::Fastify => Some("fastify"),
        _ => None,
    }
}

/// Source of the `__nyx_probe` shim for the Node.js harness.
///
/// Defined once here so both [`JavaScriptEmitter`] and
/// [`crate::dynamic::lang::typescript::TypeScriptEmitter`] reuse the same
/// JSON-emit format.  Writes a single [`crate::dynamic::probe::SinkProbe`]
/// JSON line to `NYX_PROBE_PATH` per call; no-op when the env var is
/// unset.
pub fn probe_shim() -> &'static str {
    r#"
// ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ──────
const _NYX_DENY_SUBSTRINGS = [
    'TOKEN','SECRET','PASSWORD','PASSWD','API_KEY','APIKEY','PRIVATE_KEY',
    'CREDENTIAL','SESSION','COOKIE','AUTH','BEARER','AWS_ACCESS','AWS_SESSION',
    'GH_TOKEN','GITHUB_TOKEN','NPM_TOKEN','PYPI_TOKEN','DOCKER_PASS'
];
const _NYX_PAYLOAD_LIMIT = 16 * 1024;
const _NYX_REDACTED = '<redacted-by-nyx-policy>';

function __nyx_scrub_env() {
    const out = {};
    const env = process.env || {};
    for (const k of Object.keys(env)) {
        const ku = String(k).toUpperCase();
        if (_NYX_DENY_SUBSTRINGS.some((n) => ku.indexOf(n) !== -1)) {
            out[k] = _NYX_REDACTED;
        } else {
            out[k] = env[k];
        }
    }
    return out;
}

function __nyx_witness(sinkCallee, args) {
    let payload = process.env.NYX_PAYLOAD || '';
    let buf = Buffer.from(String(payload), 'utf8');
    if (buf.length > _NYX_PAYLOAD_LIMIT) buf = buf.slice(0, _NYX_PAYLOAD_LIMIT);
    const argsRepr = args.map(function (a) {
        if (a && typeof a === 'object' && (a instanceof Buffer || a instanceof Uint8Array)) {
            return '<bytes:' + a.length + '>';
        }
        return String(a);
    });
    let cwd = '';
    try { cwd = process.cwd(); } catch (e) {}
    return {
        env_snapshot: __nyx_scrub_env(),
        cwd: cwd,
        payload_bytes: Array.from(buf),
        callee: String(sinkCallee),
        args_repr: argsRepr,
    };
}

function __nyx_emit(rec) {
    const _fs = require('fs');
    const _p = process.env.NYX_PROBE_PATH;
    if (!_p) return;
    try {
        _fs.appendFileSync(_p, JSON.stringify(rec) + '\n');
    } catch (e) {
        // best-effort: probe channel write failure is non-fatal.
    }
}

function __nyx_probe(sinkCallee, ...args) {
    const _ser = args.map(function (a) {
        if (a && typeof a === 'object' && (a instanceof Buffer || a instanceof Uint8Array)) {
            return { kind: 'Bytes', value: Array.from(a) };
        }
        if (typeof a === 'number' && Number.isInteger(a)) {
            return { kind: 'Int', value: a };
        }
        if (typeof a === 'boolean') {
            return { kind: 'Int', value: a ? 1 : 0 };
        }
        return { kind: 'String', value: String(a) };
    });
    __nyx_emit({
        sink_callee: String(sinkCallee),
        args: _ser,
        captured_at_ns: Number(process.hrtime.bigint()),
        payload_id: String(process.env.NYX_PAYLOAD_ID || ''),
        kind: { kind: 'Normal' },
        witness: __nyx_witness(sinkCallee, args),
    });
}

// Phase 08: V8 cannot catch native SIGSEGV in pure JS, but it can intercept
// `uncaughtException` / `unhandledRejection` plus the synchronously
// deliverable signals (SIGABRT via process.kill).  __nyx_install_crash_guard
// registers both: the uncaught path maps Error-shaped failures to a SIGABRT
// crash probe; explicit process.on('SIG*') registers the others where the
// runtime exposes them.  Re-raise via process.exit(134) so the outcome's
// exit_code still reflects an abort-style death.
function __nyx_install_crash_guard(sinkCallee) {
    const _emit_crash = function (signalName) {
        __nyx_emit({
            sink_callee: String(sinkCallee),
            args: [],
            captured_at_ns: Number(process.hrtime.bigint()),
            payload_id: String(process.env.NYX_PAYLOAD_ID || ''),
            kind: { kind: 'Crash', signal: signalName },
            witness: __nyx_witness(sinkCallee, []),
        });
    };
    process.on('uncaughtException', function (_err) {
        _emit_crash('SIGABRT');
        process.exit(134);
    });
    process.on('unhandledRejection', function (_reason) {
        _emit_crash('SIGABRT');
        process.exit(134);
    });
    for (const nm of ['SIGSEGV','SIGABRT','SIGBUS','SIGFPE','SIGILL']) {
        try {
            process.on(nm, function () {
                _emit_crash(nm);
                process.exit(128 + (nm === 'SIGABRT' ? 6 : 11));
            });
        } catch (e) { /* runtime refused signal handler */ }
    }
}
"#
}

/// Emit a Node.js harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_) | PayloadSlot::EnvVar(_) | PayloadSlot::Stdin => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
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
    let probe = probe_shim();

    format!(
        r#"'use strict';
// Nyx dynamic harness — auto-generated, do not edit.
{probe}

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
        probe = probe,
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
pub fn entry_module_name(_entry_file: &str) -> String {
    // The harness always `require('./entry')` because `entry_module_filename`
    // unconditionally copies the source to `entry.js` in the workdir.  Keeping
    // these two helpers in sync prevents a "Cannot find module" import error
    // when the fixture's on-disk filename is anything other than `entry.js`.
    "entry".to_owned()
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
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
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
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
    }

    #[test]
    fn emit_entry_subpath_is_entry_js() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("entry.js".to_owned()));
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!JavaScriptEmitter.entry_kinds_supported().is_empty());
        assert!(JavaScriptEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::Function));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = JavaScriptEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("phase 13"));
    }

    #[test]
    fn entry_module_name_is_always_entry_to_match_copy_destination() {
        // `copy_entry_file` (via `entry_module_filename`) stages every fixture
        // at `workdir/entry.js`, so `require('./entry')` is the only path the
        // harness can use without missing-module errors at runtime, regardless
        // of the source file's original name.
        assert_eq!(entry_module_name("src/handlers/login.js"), "entry");
        assert_eq!(entry_module_name("app.ts"), "entry");
        assert_eq!(entry_module_name("handler.mjs"), "entry");
        assert_eq!(entry_module_name("no_ext"), "entry");
    }
}
