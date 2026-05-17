//! Shared helpers for the JavaScript + TypeScript harness emitters (Phase 13).
//!
//! Both [`crate::dynamic::lang::javascript::JavaScriptEmitter`] and
//! [`crate::dynamic::lang::typescript::TypeScriptEmitter`] delegate their
//! `emit` to [`emit`] in this module — the runtime is Node.js in both cases,
//! so the harness layout is identical after type erasure.  The only divergence
//! is the entry filename: `entry.js` vs `entry.ts` so each emitter advertises
//! a typed surface even when the underlying dispatch is shared.
//!
//! Phase 13 introduces a per-file shape detector ([`JsShape`]) that inspects
//! the entry source for framework markers and picks one of seven harness
//! templates:
//!
//! - [`JsShape::Express`]: route handler `(req, res) => ...`.
//! - [`JsShape::Koa`]: middleware `async (ctx) => ...`.
//! - [`JsShape::NextRoute`]: Next.js API route default export.
//! - [`JsShape::AsyncFunction`]: bare `async function f(payload)`.
//! - [`JsShape::CommonJsExport`]: CommonJS `module.exports = { fn }` — legacy default.
//! - [`JsShape::EsModuleDefault`]: ESM `export default function f(payload)`.
//! - [`JsShape::BrowserEvent`]: DOM event handler simulated under `jsdom`.
//!
//! Shape detection is best-effort: when the entry source is unreadable or no
//! marker fires the dispatcher falls back to [`JsShape::CommonJsExport`],
//! which preserves the pre-Phase-13 behaviour.

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use crate::utils::project::DetectedFramework;
use std::path::PathBuf;

/// Concrete per-file shape resolved by reading the entry source.  One
/// harness template per variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsShape {
    /// Express handler exported by name.  Harness builds a mock req/res
    /// and dispatches synchronously.
    Express,
    /// Koa middleware exported by name.  Harness builds a mock ctx and
    /// awaits the middleware.
    Koa,
    /// Next.js API route — default-export handler `(req, res)`.  Harness
    /// builds a mock req/res; status / json / send / end captured.
    NextRoute,
    /// Bare `async function f(payload)`.  Harness awaits the result.
    AsyncFunction,
    /// `module.exports = { fn }` — pre-Phase-13 default.  Harness calls
    /// the named export synchronously.
    CommonJsExport,
    /// `export default function f(payload)` — `.mjs` / `type:module`
    /// entry.  Harness uses dynamic `import()` and unwraps `.default`.
    EsModuleDefault,
    /// DOM event handler executed inside a `jsdom` window.  Harness sets
    /// up `globalThis.window` / `document` and dispatches an event.
    BrowserEvent,
}

impl JsShape {
    /// Detect the shape from `(spec, source)`.  Framework / runtime
    /// markers in the source win over `spec.entry_kind`.
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let kind = spec.entry_kind;
        let entry = spec.entry_name.as_str();

        // ── Framework / runtime markers ─────────────────────────────
        let has_express = source_has_marker(
            source,
            &["require('express')", "require(\"express\")", "from 'express'", "from \"express\""],
        );
        let has_koa = source_has_marker(
            source,
            &["require('koa')", "require(\"koa\")", "from 'koa'", "from \"koa\""],
        );
        let has_next = source_has_marker(
            source,
            &["from 'next'", "from \"next\"", "NextApiRequest", "NextApiResponse", "// nyx-shape: next"],
        );
        let has_jsdom = source_has_marker(
            source,
            &[
                "require('jsdom')",
                "require(\"jsdom\")",
                "from 'jsdom'",
                "from \"jsdom\"",
                "document.getElementById",
                "addEventListener",
                "// nyx-shape: browser-event",
            ],
        );
        let has_esm_default = source_has_marker(
            source,
            // `module.exports = function` is intentionally NOT a marker:
            // single-function CJS exports must NOT be staged at `entry.mjs`,
            // where Node would refuse to parse the file's `require()` /
            // `module.exports` as ESM.  Legit ESM signals only.
            &["export default ", "// nyx-shape: esm-default"],
        );

        if has_express {
            return Self::Express;
        }
        if has_koa {
            return Self::Koa;
        }
        if has_next {
            return Self::NextRoute;
        }
        if has_jsdom {
            return Self::BrowserEvent;
        }

        if kind == EntryKind::HttpRoute {
            return Self::Express;
        }

        // ESM default export marker comes after framework checks so the
        // route shapes win when both apply.
        if has_esm_default && !source.contains("module.exports = {") {
            return Self::EsModuleDefault;
        }

        if function_is_async(source, entry) {
            return Self::AsyncFunction;
        }

        Self::CommonJsExport
    }
}

fn source_has_marker(source: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| source.contains(m))
}

fn function_is_async(source: &str, name: &str) -> bool {
    source.contains(&format!("async function {name}("))
        || source.contains(&format!("async {name}("))
        || source.contains(&format!("const {name} = async"))
}

// ── Probe shim (Phase 06 + Phase 08) ─────────────────────────────────────────

/// Source of the `__nyx_probe` shim for the Node.js harness.  Identical
/// for JS and TS — Node executes both after type erasure.
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

// Phase 10 (Track D.3) stub helpers.  When the verifier spawned a SqlStub it
// publishes the queries-log path through NYX_SQL_LOG; a sink call site that
// wants the host-side stub to see its query appends one record-per-call.  The
// helper is a no-op when NYX_SQL_LOG is unset so the same fixture source still
// runs under harness modes that didn't spawn a stub.  Mirrors the Python
// shim's __nyx_stub_sql_record so the host-side SqlStub log-line format
// (key/value detail lines prefixed with hash-space, followed by the query
// line) is identical across language emitters.
function __nyx_stub_sql_record(query, detail) {
    const _p = process.env.NYX_SQL_LOG;
    if (!_p) return;
    const _fs = require('fs');
    try {
        let _buf = '';
        if (detail && typeof detail === 'object') {
            for (const _k of Object.keys(detail)) {
                _buf += '# ' + String(_k) + ': ' + String(detail[_k]) + '\n';
            }
        }
        const _q = String(query);
        _buf += _q;
        if (!_q.endsWith('\n')) _buf += '\n';
        _fs.appendFileSync(_p, _buf);
    } catch (e) {
        // best-effort: stub recorder write failure is non-fatal.
    }
}

// Phase 10 (Track D.3) HTTP recording helper.  When the verifier spawned an
// HttpStub it publishes the side-channel log path through NYX_HTTP_LOG; a
// sink call site whose outbound request never reaches the on-the-wire
// listener (DNS-mocked, network-isolated sandbox, pre-flight check) can
// call this helper to surface the attempted call.  Format matches the SQL
// helper so the host-side merger parses both streams identically.
function __nyx_stub_http_record(method, url, body, detail) {
    const _p = process.env.NYX_HTTP_LOG;
    if (!_p) return;
    const _fs = require('fs');
    try {
        let _buf = '';
        _buf += '# method: ' + String(method) + '\n';
        _buf += '# url: ' + String(url) + '\n';
        if (body !== undefined && body !== null) {
            _buf += '# body: ' + String(body) + '\n';
        }
        if (detail && typeof detail === 'object') {
            for (const _k of Object.keys(detail)) {
                _buf += '# ' + String(_k) + ': ' + String(detail[_k]) + '\n';
            }
        }
        _buf += String(method) + ' ' + String(url) + '\n';
        _fs.appendFileSync(_p, _buf);
    } catch (e) {
        // best-effort: stub recorder write failure is non-fatal.
    }
}
"#
}

// ── Runtime / package.json synthesis (Phase 09) ─────────────────────────────

/// Phase 09 — Track D.2: emit a `package.json` covering every captured
/// dep plus the framework deps inferred from the manifest detector.
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
        "fs" | "path" | "http" | "https" | "url" | "crypto" | "stream"
            | "util" | "child_process" | "os" | "events" | "buffer"
            | "querystring" | "zlib" | "assert" | "process" | "net"
            | "tls" | "dns" | "readline" | "tty"
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

// ── Per-shape `extra_files` (Phase 13 — Track B JS / TS vertical) ───────────

/// `package.json` + `package-lock.json` for shapes that bring in a real
/// framework dep.  The harness builder folds these into the workdir via
/// the existing `extra_files` mechanism and `prepare_node` then runs
/// `npm install` against them.
fn extra_files_for_shape(shape: JsShape) -> Vec<(String, String)> {
    match shape {
        JsShape::Express => vec![
            ("package.json".to_owned(), package_json_for("express", "^4.19.2")),
            ("package-lock.json".to_owned(), package_lock_skeleton("nyx-harness-express")),
        ],
        JsShape::Koa => vec![
            ("package.json".to_owned(), package_json_for("koa", "^2.15.3")),
            ("package-lock.json".to_owned(), package_lock_skeleton("nyx-harness-koa")),
        ],
        JsShape::NextRoute => vec![
            ("package.json".to_owned(), package_json_for("next", "^14.2.5")),
            ("package-lock.json".to_owned(), package_lock_skeleton("nyx-harness-next")),
        ],
        JsShape::BrowserEvent => vec![
            ("package.json".to_owned(), package_json_for("jsdom", "^24.1.1")),
            ("package-lock.json".to_owned(), package_lock_skeleton("nyx-harness-jsdom")),
        ],
        // Plain async / CJS / ESM use stdlib only.
        _ => vec![],
    }
}

fn package_json_for(dep: &str, version: &str) -> String {
    format!(
        "{{\n  \"name\": \"nyx-harness-{dep}\",\n  \"version\": \"0.0.0\",\n  \"private\": true,\n  \"dependencies\": {{\n    \"{dep}\": \"{version}\"\n  }}\n}}\n",
    )
}

fn package_lock_skeleton(name: &str) -> String {
    // Bare lockfile structure.  npm rewrites this on first install; checking
    // it in keeps the per-shape fixture directory self-describing.
    format!(
        "{{\n  \"name\": \"{name}\",\n  \"version\": \"0.0.0\",\n  \"lockfileVersion\": 3,\n  \"requires\": true,\n  \"packages\": {{\n    \"\": {{\n      \"name\": \"{name}\",\n      \"version\": \"0.0.0\"\n    }}\n  }}\n}}\n",
    )
}

// ── Public entry: emit() ─────────────────────────────────────────────────────

/// Emit a Node.js harness for `spec`.  `is_typescript` controls only the
/// entry filename (`entry.ts` vs `entry.js`) — the harness itself is JS
/// either way, and the runner relies on Node's CommonJS extension being
/// permissive enough to load both.
pub fn emit(spec: &HarnessSpec, is_typescript: bool) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_)
        | PayloadSlot::EnvVar(_)
        | PayloadSlot::Stdin
        | PayloadSlot::QueryParam(_)
        | PayloadSlot::HttpBody
        | PayloadSlot::Argv(_) => {}
    }

    // Phase 04 (Track J.2): SSTI-sink short-circuit for Handlebars.
    if spec.expected_cap == crate::labels::Cap::SSTI {
        return Ok(emit_ssti_harness(spec));
    }

    let entry_source = read_entry_source(&spec.entry_file);
    let shape = JsShape::detect(spec, &entry_source);
    let entry_subpath = entry_subpath_for_shape(shape, is_typescript);
    let body = generate_for_shape(spec, shape, &entry_subpath);

    Ok(HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: extra_files_for_shape(shape),
        entry_subpath: Some(entry_subpath),
    })
}

/// Phase 04 — Track J.2 SSTI harness for Node (Handlebars).
///
/// Reads `NYX_PAYLOAD`, simulates Handlebars's `{{helper a b}}`
/// evaluation against a tiny `multiply` / `add` helper table, prints
/// `{"render":"<result>"}` plus the sink-hit sentinel.  Synthetic
/// renderer keeps the corpus deterministic without bundling
/// Handlebars in the sandbox image.
pub fn emit_ssti_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"// Nyx dynamic harness — SSTI Handlebars (Phase 04 / Track J.2).
{shim}

function nyxHandlebarsRender(payload) {{
  return payload.replace(/\{{\{{(.+?)\}}\}}/g, function (_, raw) {{
    const expr = raw.trim();
    const helperMatch = expr.match(/^(\w+)\s+(\d+)\s+(\d+)$/);
    if (helperMatch) {{
      const a = parseInt(helperMatch[2], 10);
      const b = parseInt(helperMatch[3], 10);
      if (helperMatch[1] === 'multiply') return String(a * b);
      if (helperMatch[1] === 'add') return String(a + b);
    }}
    return _;
  }});
}}

function nyxSstiProbe(rendered) {{
  const p = process.env.NYX_PROBE_PATH;
  if (!p) return;
  const rec = {{
    sink_callee: 'Handlebars.compile',
    args: [{{ kind: 'String', value: rendered }}],
    captured_at_ns: Date.now() * 1_000_000,
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{ kind: 'Normal' }},
    witness: __nyx_witness('Handlebars.compile', [rendered]),
  }};
  try {{
    require('fs').appendFileSync(p, JSON.stringify(rec) + '\n');
  }} catch (e) {{
    // best-effort
  }}
}}

const payload = process.env.NYX_PAYLOAD || '';
const rendered = nyxHandlebarsRender(payload);
nyxSstiProbe(rendered);
console.log('__NYX_SINK_HIT__');
console.log(JSON.stringify({{ render: rendered }}));
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 26 — Node chain-step harness (shared between JS + TS emitters).
///
/// Splices the Node probe shim ([`probe_shim`]) in front of a minimal
/// driver that reads `NYX_PREV_OUTPUT` and forwards it on stdout.  When
/// the step is the chain's terminal step the driver also calls
/// `__nyx_probe(callee, prev)` and prints the
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] so the runner flips
/// `sink_hit` for the chain.
pub fn chain_step(
    prev_output: Option<&[u8]>,
    is_typescript: bool,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let probe = probe_shim();
    let mut driver = String::from(
        "\nconst __nyx_prev = process.env.NYX_PREV_OUTPUT || '';\nprocess.stdout.write(__nyx_prev);\n",
    );
    if let Some(t) = terminal {
        let callee = js_string_literal(&t.sink_callee);
        let sentinel = js_string_literal(ChainStepHarness::SINK_HIT_SENTINEL);
        driver.push_str(&format!(
            "__nyx_probe({callee}, __nyx_prev);\nconsole.log({sentinel});\n",
        ));
    }
    // The chain-step source is pure JS even under the TypeScript emitter
    // — the probe shim uses no TS-specific syntax — so we keep the `.ts`
    // filename intent (so the workdir reflects which emitter produced
    // the step) but stage a `.js` sibling and run that.  Without this,
    // `node step.ts` fails on stock Node before 22.6 (the
    // `--experimental-strip-types` flag) and on any host that has not
    // installed `tsx` / `ts-node`.
    let (filename, command) = if is_typescript {
        (
            "step.ts".to_owned(),
            vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "cp step.ts step.js && node step.js".to_owned(),
            ],
        )
    } else {
        (
            "step.js".to_owned(),
            vec!["node".to_owned(), "step.js".to_owned()],
        )
    };
    ChainStepHarness {
        source: format!("{probe}{driver}"),
        filename,
        command,
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

/// Escape a string for safe JS double-quoted literal embedding.
fn js_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Public wrapper to detect the shape for a finalised [`HarnessSpec`].
pub fn detect_shape(spec: &HarnessSpec) -> JsShape {
    let entry_source = read_entry_source(&spec.entry_file);
    JsShape::detect(spec, &entry_source)
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

/// File name the harness's `require` / `import()` will reach for.
///
/// Both JS and TS fixtures stage their entry source at `workdir/entry.js`
/// so Node's CommonJS `require('./entry')` resolves without registering a
/// loader extension hook.  TS fixtures therefore use ES-compatible syntax
/// (no type annotations) — the `.ts` extension on the source-side fixture
/// file is purely cosmetic for the per-language test bucket.  ESM-default
/// shapes get `entry.mjs` because dynamic `import()` is extension-sensitive
/// and Node only enters strict-ESM mode for `.mjs`.
fn entry_subpath_for_shape(shape: JsShape, _is_typescript: bool) -> String {
    match shape {
        JsShape::EsModuleDefault => "entry.mjs".to_owned(),
        _ => "entry.js".to_owned(),
    }
}

fn generate_for_shape(spec: &HarnessSpec, shape: JsShape, entry_subpath: &str) -> String {
    let preamble = harness_preamble(entry_subpath, shape);
    let body = match shape {
        JsShape::CommonJsExport => emit_commonjs(spec),
        JsShape::AsyncFunction => emit_async(spec),
        JsShape::EsModuleDefault => emit_esm_default(spec),
        JsShape::Express => emit_express(spec),
        JsShape::Koa => emit_koa(spec),
        JsShape::NextRoute => emit_next(spec),
        JsShape::BrowserEvent => emit_browser_event(spec),
    };
    format!("{preamble}\n{body}\n")
}

/// Shared preamble: shim, payload loader, entry import.  ESM default
/// shape opts out of the eager require and pulls the module in via
/// dynamic `import()` from its own body.
fn harness_preamble(entry_subpath: &str, shape: JsShape) -> String {
    let probe = probe_shim();
    let entry_require_path = entry_require_path(entry_subpath);
    let import_block = match shape {
        JsShape::EsModuleDefault => String::new(),
        _ => format!(
            r#"let _entry;
try {{
    _entry = require('./{entry_require_path}');
}} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
}}
"#
        ),
    };

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
const payload = _nyx_payload;

{import_block}
"#
    )
}

/// Strip the file extension so `require('./entry')` resolves regardless
/// of whether the on-disk file is `.js` or `.ts` (Node's CJS loader
/// honours either when the extension is omitted).  The ESM-default
/// shape uses the full `entry.mjs` path because dynamic `import()` is
/// extension-sensitive.
fn entry_require_path(entry_subpath: &str) -> String {
    if let Some(stripped) = entry_subpath.strip_suffix(".js") {
        return stripped.to_owned();
    }
    if let Some(stripped) = entry_subpath.strip_suffix(".ts") {
        return stripped.to_owned();
    }
    entry_subpath.to_owned()
}

// ── Per-shape bodies ─────────────────────────────────────────────────────────

fn emit_commonjs(spec: &HarnessSpec) -> String {
    let (pre_call, call_expr) = build_call(spec, &spec.entry_name);
    format!(
        r#"// Shape: CommonJS export — module.exports = {{ fn }}.
{pre_call}
try {{
    const _result = {call_expr};
    if (_result && typeof _result.then === 'function') {{
        _result
            .then((r) => {{ if (r != null) process.stdout.write(String(r) + '\n'); }})
            .catch((e) => process.stderr.write('NYX_EXCEPTION: ' + e.message + '\n'));
    }} else if (_result != null) {{
        process.stdout.write(String(_result) + '\n');
    }}
}} catch (e) {{
    process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
}}
"#
    )
}

fn emit_async(spec: &HarnessSpec) -> String {
    let (pre_call, call_expr) = build_call(spec, &spec.entry_name);
    format!(
        r#"// Shape: async function — await the coroutine.
{pre_call}
(async () => {{
    try {{
        const _result = await {call_expr};
        if (_result != null) process.stdout.write(String(_result) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#
    )
}

fn emit_esm_default(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (pre_call, call_args) = build_call_args(spec);
    format!(
        r#"// Shape: ES module default export — dynamic import().
{pre_call}
(async () => {{
    let _mod;
    try {{
        _mod = await import('./entry.mjs');
    }} catch (e) {{
        process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
        process.exit(77);
    }}
    const _fn = _mod.default || _mod[{entry_fn:?}];
    if (typeof _fn !== 'function') {{
        process.stderr.write('NYX_ENTRY_NOT_CALLABLE\n');
        process.exit(78);
    }}
    try {{
        const _result = await _fn({call_args});
        if (_result != null) process.stdout.write(String(_result) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#
    )
}

fn emit_express(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (method, payload_key, body_kind) = resolve_http_payload(&spec.payload_slot);
    format!(
        r#"// Shape: Express handler — mock req/res and dispatch synchronously.
const _handler = _entry[{entry_fn:?}] || _entry.default || _entry;
if (typeof _handler !== 'function') {{
    process.stderr.write('NYX_EXPRESS_HANDLER_NOT_FOUND\n');
    process.exit(78);
}}
const _kind = {body_kind:?};
const _payload_key = {payload_key:?};
const _req = {{
    method: {method:?},
    query: {{}},
    body: {{}},
    params: {{}},
    headers: {{}},
    url: '/',
}};
if (_kind === 'query') {{
    _req.query[_payload_key] = payload;
    _req.url = '/?' + encodeURIComponent(_payload_key) + '=' + encodeURIComponent(payload);
}} else if (_kind === 'body') {{
    _req.body = payload;
}} else if (_kind === 'env') {{
    process.env[_payload_key] = payload;
}} else if (_kind === 'param') {{
    _req.params[_payload_key] = payload;
}}
let _captured = '';
const _res = {{
    statusCode: 200,
    headers: {{}},
    status: function (c) {{ this.statusCode = c; return this; }},
    set: function (k, v) {{ this.headers[k] = v; return this; }},
    setHeader: function (k, v) {{ this.headers[k] = v; }},
    send: function (b) {{ _captured += String(b == null ? '' : b); return this; }},
    end: function (b) {{ if (b != null) _captured += String(b); return this; }},
    json: function (o) {{ _captured += JSON.stringify(o); return this; }},
    write: function (b) {{ _captured += String(b == null ? '' : b); return this; }},
}};
(async () => {{
    try {{
        const _result = _handler(_req, _res, function () {{}});
        if (_result && typeof _result.then === 'function') await _result;
        process.stdout.write(_captured + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#
    )
}

fn emit_koa(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (method, payload_key, body_kind) = resolve_http_payload(&spec.payload_slot);
    format!(
        r#"// Shape: Koa middleware — mock ctx and await dispatch.
const _mw = _entry[{entry_fn:?}] || _entry.default || _entry;
if (typeof _mw !== 'function') {{
    process.stderr.write('NYX_KOA_HANDLER_NOT_FOUND\n');
    process.exit(78);
}}
const _kind = {body_kind:?};
const _payload_key = {payload_key:?};
const _ctx = {{
    method: {method:?},
    query: {{}},
    request: {{ body: {{}}, query: {{}}, header: {{}} }},
    params: {{}},
    headers: {{}},
    body: '',
    status: 200,
    set: function (k, v) {{ this.headers[k] = v; }},
}};
if (_kind === 'query') {{
    _ctx.query[_payload_key] = payload;
    _ctx.request.query[_payload_key] = payload;
}} else if (_kind === 'body') {{
    _ctx.request.body = payload;
}} else if (_kind === 'env') {{
    process.env[_payload_key] = payload;
}} else if (_kind === 'param') {{
    _ctx.params[_payload_key] = payload;
}}
(async () => {{
    try {{
        await _mw(_ctx, async function () {{}});
        process.stdout.write(String(_ctx.body == null ? '' : _ctx.body) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#
    )
}

fn emit_next(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (method, payload_key, body_kind) = resolve_http_payload(&spec.payload_slot);
    format!(
        r#"// Shape: Next.js API route — default export (req, res).
const _handler = _entry.default || _entry[{entry_fn:?}] || _entry;
if (typeof _handler !== 'function') {{
    process.stderr.write('NYX_NEXT_HANDLER_NOT_FOUND\n');
    process.exit(78);
}}
const _kind = {body_kind:?};
const _payload_key = {payload_key:?};
const _req = {{
    method: {method:?},
    query: {{}},
    body: {{}},
    headers: {{}},
    url: '/',
}};
if (_kind === 'query') {{
    _req.query[_payload_key] = payload;
}} else if (_kind === 'body') {{
    _req.body = payload;
}} else if (_kind === 'env') {{
    process.env[_payload_key] = payload;
}}
let _captured = '';
const _res = {{
    statusCode: 200,
    headers: {{}},
    status: function (c) {{ this.statusCode = c; return this; }},
    setHeader: function (k, v) {{ this.headers[k] = v; }},
    send: function (b) {{ _captured += String(b == null ? '' : b); return this; }},
    end: function (b) {{ if (b != null) _captured += String(b); return this; }},
    json: function (o) {{ _captured += JSON.stringify(o); return this; }},
    write: function (b) {{ _captured += String(b == null ? '' : b); return this; }},
}};
(async () => {{
    try {{
        const _result = _handler(_req, _res);
        if (_result && typeof _result.then === 'function') await _result;
        process.stdout.write(_captured + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#
    )
}

fn emit_browser_event(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (pre_call, call_args) = build_call_args(spec);
    format!(
        r#"// Shape: browser-side event handler — simulate under jsdom.
let _JSDOM;
try {{
    _JSDOM = require('jsdom').JSDOM;
}} catch (e) {{
    process.stderr.write('NYX_JSDOM_MISSING: ' + e.message + '\n');
    process.exit(79);
}}
const _dom = new _JSDOM('<!doctype html><html><body><div id="out"></div></body></html>', {{
    runScripts: 'outside-only',
    pretendToBeVisual: true,
    url: 'http://nyx.test/',
}});
globalThis.window = _dom.window;
globalThis.document = _dom.window.document;
globalThis.HTMLElement = _dom.window.HTMLElement;
globalThis.Event = _dom.window.Event;

{pre_call}
(async () => {{
    try {{
        const _fn = _entry[{entry_fn:?}] || _entry.default || _entry;
        if (typeof _fn !== 'function') {{
            process.stderr.write('NYX_BROWSER_HANDLER_NOT_FOUND\n');
            process.exit(78);
        }}
        await _fn({call_args});
        // Mirror the resulting DOM to stdout so the oracle sees the
        // payload only when it was actually injected into innerHTML.
        // Intentionally do NOT print the handler's return value — a
        // `textContent` (benign) sink returns the raw payload string and
        // would otherwise smuggle the XSS marker past the DOM escape.
        const _out = _dom.window.document.body.innerHTML;
        process.stdout.write(_out + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#
    )
}

// ── Slot resolution helpers ──────────────────────────────────────────────────

fn build_call(spec: &HarnessSpec, func: &str) -> (String, String) {
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
            let pre = "const { Readable } = require('stream');\nprocess.stdin = Readable.from([Buffer.from(payload, 'utf8')]);\n".to_owned();
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

fn build_call_args(spec: &HarnessSpec) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(idx) => {
            let pre = String::new();
            let args = if *idx == 0 {
                "payload".to_owned()
            } else {
                let pads = (0..*idx).map(|_| "''").collect::<Vec<_>>().join(", ");
                format!("{pads}, payload")
            };
            (pre, args)
        }
        PayloadSlot::EnvVar(name) => {
            let pre = format!("process.env[{name:?}] = payload;\n");
            (pre, String::new())
        }
        PayloadSlot::Stdin => {
            let pre = "const { Readable } = require('stream');\nprocess.stdin = Readable.from([Buffer.from(payload, 'utf8')]);\n".to_owned();
            (pre, String::new())
        }
        _ => (String::new(), "payload".to_owned()),
    }
}

/// Resolve `(http_method, payload_key, body_kind)` for the HTTP-shaped
/// emitters.  `body_kind` is one of `"query"`, `"body"`, `"env"`, or
/// `"param"`.
fn resolve_http_payload(slot: &PayloadSlot) -> (&'static str, String, &'static str) {
    match slot {
        PayloadSlot::QueryParam(name) => ("GET", name.clone(), "query"),
        PayloadSlot::HttpBody => ("POST", String::new(), "body"),
        PayloadSlot::EnvVar(name) => ("GET", name.clone(), "env"),
        PayloadSlot::Param(_) => ("GET", "host".to_owned(), "param"),
        _ => ("GET", "q".to_owned(), "query"),
    }
}

/// Supported entry kinds for both JS + TS after Phase 13.
pub const SUPPORTED: &[EntryKind] = &[
    EntryKind::Function,
    EntryKind::HttpRoute,
    EntryKind::CliSubcommand,
    EntryKind::LibraryApi,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(kind: EntryKind, name: &str, slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "jsshared0000001".into(),
            entry_file: "src/app.js".into(),
            entry_name: name.into(),
            entry_kind: kind,
            lang: Lang::JavaScript,
            toolchain_id: "node-20".into(),
            payload_slot: slot,
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: "src/app.js".into(),
            sink_line: 12,
            spec_hash: "jsshared00000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
        }
    }

    #[test]
    fn detect_express_via_require() {
        let src = "const express = require('express');\nfunction ping(req, res) {}";
        let spec = make_spec(EntryKind::Function, "ping", PayloadSlot::QueryParam("host".into()));
        assert_eq!(JsShape::detect(&spec, src), JsShape::Express);
    }

    #[test]
    fn detect_koa_via_require() {
        let src = "const Koa = require('koa');\nasync function ping(ctx) {}";
        let spec = make_spec(EntryKind::Function, "ping", PayloadSlot::QueryParam("host".into()));
        assert_eq!(JsShape::detect(&spec, src), JsShape::Koa);
    }

    #[test]
    fn detect_next_via_marker() {
        let src = "// nyx-shape: next\nmodule.exports = async function handler(req, res) {};";
        let spec = make_spec(EntryKind::HttpRoute, "handler", PayloadSlot::QueryParam("host".into()));
        assert_eq!(JsShape::detect(&spec, src), JsShape::NextRoute);
    }

    #[test]
    fn detect_browser_via_jsdom_marker() {
        let src = "// nyx-shape: browser-event\nfunction onClick(p) { document.getElementById('out').innerHTML = p; }";
        let spec = make_spec(EntryKind::Function, "onClick", PayloadSlot::Param(0));
        assert_eq!(JsShape::detect(&spec, src), JsShape::BrowserEvent);
    }

    #[test]
    fn detect_async_function() {
        let src = "async function runPing(host) { return host; }\nmodule.exports = { runPing };";
        let spec = make_spec(EntryKind::Function, "runPing", PayloadSlot::Param(0));
        assert_eq!(JsShape::detect(&spec, src), JsShape::AsyncFunction);
    }

    #[test]
    fn detect_esm_default_export() {
        let src = "// nyx-shape: esm-default\nexport default function runPing(host) { return host; }";
        let spec = make_spec(EntryKind::Function, "runPing", PayloadSlot::Param(0));
        assert_eq!(JsShape::detect(&spec, src), JsShape::EsModuleDefault);
    }

    #[test]
    fn detect_commonjs_fallback() {
        let src = "function login(x) {}\nmodule.exports = { login };";
        let spec = make_spec(EntryKind::Function, "login", PayloadSlot::Param(0));
        assert_eq!(JsShape::detect(&spec, src), JsShape::CommonJsExport);
    }

    #[test]
    fn emit_express_uses_mock_req_res() {
        let spec = make_spec(EntryKind::HttpRoute, "ping", PayloadSlot::QueryParam("host".into()));
        let src = generate_for_shape(&spec, JsShape::Express, "entry.js");
        assert!(src.contains("Express handler"));
        assert!(src.contains("_req.query[_payload_key] = payload"));
    }

    #[test]
    fn emit_koa_awaits_middleware() {
        let spec = make_spec(EntryKind::HttpRoute, "ping", PayloadSlot::QueryParam("host".into()));
        let src = generate_for_shape(&spec, JsShape::Koa, "entry.js");
        assert!(src.contains("await _mw(_ctx"));
    }

    #[test]
    fn emit_esm_default_uses_dynamic_import() {
        let spec = make_spec(EntryKind::Function, "runPing", PayloadSlot::Param(0));
        let src = generate_for_shape(&spec, JsShape::EsModuleDefault, "entry.mjs");
        assert!(src.contains("await import('./entry.mjs')"));
    }

    #[test]
    fn emit_browser_event_installs_jsdom() {
        let spec = make_spec(EntryKind::Function, "onClick", PayloadSlot::Param(0));
        let src = generate_for_shape(&spec, JsShape::BrowserEvent, "entry.js");
        assert!(src.contains("new _JSDOM"));
        assert!(src.contains("globalThis.document"));
    }

    #[test]
    fn extra_files_for_express_has_package_json() {
        let extras = extra_files_for_shape(JsShape::Express);
        assert!(extras.iter().any(|(p, c)| p == "package.json" && c.contains("express")));
        assert!(extras.iter().any(|(p, _)| p == "package-lock.json"));
    }

    #[test]
    fn extra_files_for_commonjs_is_empty() {
        let extras = extra_files_for_shape(JsShape::CommonJsExport);
        assert!(extras.is_empty());
    }

    #[test]
    fn entry_require_path_strips_extension() {
        assert_eq!(entry_require_path("entry.js"), "entry");
        assert_eq!(entry_require_path("entry.ts"), "entry");
        assert_eq!(entry_require_path("entry.mjs"), "entry.mjs");
    }

    #[test]
    fn emit_returns_node_command() {
        let spec = make_spec(EntryKind::Function, "login", PayloadSlot::Param(0));
        let h = emit(&spec, false).unwrap();
        assert_eq!(h.filename, "harness.js");
        assert_eq!(h.command, vec!["node", "harness.js"]);
    }

    #[test]
    fn typescript_and_javascript_share_entry_js_subpath() {
        let spec = make_spec(EntryKind::Function, "login", PayloadSlot::Param(0));
        let h_js = emit(&spec, false).unwrap();
        let h_ts = emit(&spec, true).unwrap();
        assert_eq!(h_js.entry_subpath, h_ts.entry_subpath);
        assert_eq!(h_js.entry_subpath.as_deref(), Some("entry.js"));
    }

    #[test]
    fn probe_shim_publishes_stub_sql_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("function __nyx_stub_sql_record"),
            "Node probe shim must define __nyx_stub_sql_record"
        );
        assert!(
            shim.contains("NYX_SQL_LOG"),
            "stub recorder must read NYX_SQL_LOG"
        );
        assert!(
            shim.contains("appendFileSync"),
            "stub recorder must append to the log file"
        );
    }

    #[test]
    fn probe_shim_publishes_stub_http_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("function __nyx_stub_http_record"),
            "Node probe shim must define __nyx_stub_http_record"
        );
        assert!(
            shim.contains("NYX_HTTP_LOG"),
            "stub recorder must read NYX_HTTP_LOG"
        );
    }
}
