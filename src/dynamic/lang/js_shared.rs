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
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
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
    /// Fastify route plugin.  Harness loads the entry's `app` export
    /// (which must be a configured Fastify instance) and replays the
    /// spec's request through Fastify's built-in
    /// [`light-my-request`](https://github.com/fastify/light-my-request)
    /// equivalent — `app.inject({ method, url, query, payload, headers })`.
    /// No external `supertest` dep is required because `inject` ships in
    /// Fastify core.  Phase 13 — Track L.11.
    Fastify,
    /// NestJS controller class.  Harness loads the entry's exported
    /// controller class, mounts it via `Test.createTestingModule`, and
    /// replays the spec's request through `supertest(app.getHttpServer())`.
    /// Phase 13 — Track L.11.
    Nest,
}

impl JsShape {
    /// Detect the shape from `(spec, source)`.  Framework / runtime
    /// markers in the source win over `spec.entry_kind`.
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let kind = spec.entry_kind.tag();
        let entry = spec.entry_name.as_str();

        // ── Framework / runtime markers ─────────────────────────────
        let has_express = source_has_marker(
            source,
            &[
                "require('express')",
                "require(\"express\")",
                "from 'express'",
                "from \"express\"",
            ],
        );
        let has_koa = source_has_marker(
            source,
            &[
                "require('koa')",
                "require(\"koa\")",
                "from 'koa'",
                "from \"koa\"",
            ],
        );
        let has_fastify = source_has_marker(
            source,
            &[
                "require('fastify')",
                "require(\"fastify\")",
                "from 'fastify'",
                "from \"fastify\"",
                "// nyx-shape: fastify",
            ],
        );
        let has_nest = source_has_marker(
            source,
            &[
                "@nestjs/common",
                "@nestjs/core",
                "@nestjs/platform-express",
                "@nestjs/platform-fastify",
                "NestFactory",
                "@Controller",
                "// nyx-shape: nest",
            ],
        );
        let has_next = source_has_marker(
            source,
            &[
                "from 'next'",
                "from \"next\"",
                "NextApiRequest",
                "NextApiResponse",
                "// nyx-shape: next",
            ],
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

        // Nest wins over Express / Fastify because Nest projects also
        // import `@nestjs/platform-express` / `@nestjs/platform-fastify`
        // transitively — the controller-class shape needs its own
        // testing module bootstrap.
        if has_nest {
            return Self::Nest;
        }
        if has_fastify {
            return Self::Fastify;
        }
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

        if kind == EntryKindTag::HttpRoute {
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
        if let Some(name) = node_framework_pkg_name(*fw)
            && seen.insert(name.to_owned())
        {
            deps.push((name.to_owned(), "*"));
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
        "fs" | "path"
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

// ── Per-shape `extra_files` (Phase 13 — Track B JS / TS vertical) ───────────

/// `package.json` + `package-lock.json` for shapes that bring in a real
/// framework dep.  The harness builder folds these into the workdir via
/// the existing `extra_files` mechanism and `prepare_node` then runs
/// `npm install` against them.
fn extra_files_for_shape(shape: JsShape) -> Vec<(String, String)> {
    match shape {
        JsShape::Express => vec![
            (
                "package.json".to_owned(),
                package_json_for("express", "^4.19.2"),
            ),
            (
                "package-lock.json".to_owned(),
                package_lock_skeleton("nyx-harness-express"),
            ),
        ],
        JsShape::Koa => vec![
            (
                "package.json".to_owned(),
                package_json_for("koa", "^2.15.3"),
            ),
            (
                "package-lock.json".to_owned(),
                package_lock_skeleton("nyx-harness-koa"),
            ),
        ],
        JsShape::NextRoute => vec![
            (
                "package.json".to_owned(),
                package_json_for("next", "^14.2.5"),
            ),
            (
                "package-lock.json".to_owned(),
                package_lock_skeleton("nyx-harness-next"),
            ),
        ],
        JsShape::BrowserEvent => vec![
            (
                "package.json".to_owned(),
                package_json_for("jsdom", "^24.1.1"),
            ),
            (
                "package-lock.json".to_owned(),
                package_lock_skeleton("nyx-harness-jsdom"),
            ),
        ],
        JsShape::Fastify => vec![
            (
                "package.json".to_owned(),
                package_json_for("fastify", "^4.28.1"),
            ),
            (
                "package-lock.json".to_owned(),
                package_lock_skeleton("nyx-harness-fastify"),
            ),
        ],
        JsShape::Nest => vec![
            (
                "package.json".to_owned(),
                package_json_multi(
                    "nyx-harness-nest",
                    &[
                        ("@nestjs/common", "^10.0.0"),
                        ("@nestjs/core", "^10.0.0"),
                        ("@nestjs/platform-express", "^10.0.0"),
                        ("@nestjs/testing", "^10.0.0"),
                        ("supertest", "^7.0.0"),
                        ("reflect-metadata", "^0.2.0"),
                        ("rxjs", "^7.8.0"),
                    ],
                ),
            ),
            (
                "package-lock.json".to_owned(),
                package_lock_skeleton("nyx-harness-nest"),
            ),
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

fn package_json_multi(pkg_name: &str, deps: &[(&str, &str)]) -> String {
    let mut body = String::with_capacity(128);
    body.push_str("{\n  \"name\": \"");
    body.push_str(pkg_name);
    body.push_str("\",\n  \"version\": \"0.0.0\",\n  \"private\": true,\n  \"dependencies\": {\n");
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
    body.push_str("  }\n}\n");
    body
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

    // Phase 07 (Track J.5): XPATH_INJECTION-sink short-circuit.  The
    // synthetic harness inlines a tiny XPath evaluator and counts
    // matching nodes against the canonical staged document.
    if spec.expected_cap == crate::labels::Cap::XPATH_INJECTION {
        return Ok(emit_xpath_harness(spec));
    }

    // Phase 08 (Track J.6): HEADER_INJECTION-sink short-circuit.  The
    // synthetic harness calls an instrumented `res.setHeader` shim
    // that records the unmodified value bytes via a
    // `ProbeKind::HeaderEmit` probe.
    if spec.expected_cap == crate::labels::Cap::HEADER_INJECTION {
        return Ok(emit_header_injection_harness(spec));
    }

    // Phase 09 (Track J.7): OPEN_REDIRECT-sink short-circuit.  The
    // synthetic harness calls an instrumented `res.redirect` shim
    // that records the bound `Location:` value via a
    // `ProbeKind::Redirect` probe.
    if spec.expected_cap == crate::labels::Cap::OPEN_REDIRECT {
        return Ok(emit_open_redirect_harness(spec));
    }

    // Phase 10 (Track J.8): PROTOTYPE_POLLUTION-sink short-circuit.
    // The synthetic harness installs a `Proxy`-style setter trap on
    // `Object.prototype.__nyx_canary` and runs a naive deep-merge
    // sink that walks the payload's top-level keys into a vanilla
    // target object.  A vuln payload whose JSON literal contains
    // `__proto__` traverses the chain and trips the trap; a benign
    // payload whose JSON literal carries only regular keys leaves
    // the prototype untouched.
    if spec.expected_cap == crate::labels::Cap::PROTOTYPE_POLLUTION {
        return Ok(emit_prototype_pollution_harness(spec));
    }

    // Phase 19 (Track M.1): ClassMethod short-circuit.  Same shape gap
    // closer as the Python emitter — instantiate the class via its
    // zero-arg constructor (falling back to a stubbed-dependency ctor
    // when the zero-arg path throws) and invoke `method(payload)`.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method(spec, class, method, is_typescript));
    }

    // Phase 20 (Track M.2): MessageHandler short-circuit.  Mounts the
    // in-process SQS loopback (the only broker Node has a dedicated
    // adapter for in this phase) and dispatches the payload to the
    // named handler synchronously.
    if let crate::evidence::EntryKind::MessageHandler { queue, .. } = &spec.entry_kind {
        return Ok(emit_message_handler(spec, queue, is_typescript));
    }

    // Phase 21 (Track M.3): ScheduledJob short-circuit.
    if let crate::evidence::EntryKind::ScheduledJob { schedule } = &spec.entry_kind {
        return Ok(emit_scheduled_job(spec, schedule.as_deref(), is_typescript));
    }

    // Phase 21 (Track M.3): GraphQLResolver short-circuit.
    if let crate::evidence::EntryKind::GraphQLResolver { type_name, field } = &spec.entry_kind {
        return Ok(emit_graphql_resolver(spec, type_name, field, is_typescript));
    }

    // Phase 21 (Track M.3): WebSocket short-circuit.
    if let crate::evidence::EntryKind::WebSocket { path } = &spec.entry_kind {
        return Ok(emit_websocket_handler(spec, path, is_typescript));
    }

    // Phase 21 (Track M.3): Middleware short-circuit.
    if let crate::evidence::EntryKind::Middleware { name } = &spec.entry_kind {
        return Ok(emit_middleware(spec, name, is_typescript));
    }

    // Phase 21 (Track M.3): Migration short-circuit.
    if let crate::evidence::EntryKind::Migration { version } = &spec.entry_kind {
        return Ok(emit_migration(spec, version.as_deref(), is_typescript));
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

/// Phase 19 (Track M.1) — class-method harness for Node.js / TypeScript.
///
/// Imports the entry module, locates `class` on the exported surface,
/// instantiates via the default constructor, falls back to a single
/// mock-dependency ctor when the zero-arg path throws, and invokes
/// `instance[method](payload)`.
fn emit_class_method(
    _spec: &HarnessSpec,
    class: &str,
    method: &str,
    is_typescript: bool,
) -> HarnessSource {
    let probe = probe_shim();
    let entry_subpath = if is_typescript {
        "entry.ts"
    } else {
        "entry.js"
    };
    let entry_require_path = entry_require_path(entry_subpath);
    let mock_http = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::HttpClient,
        crate::symbol::Lang::JavaScript,
    );
    let mock_db = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::DatabaseConnection,
        crate::symbol::Lang::JavaScript,
    );
    let mock_log = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::Logger,
        crate::symbol::Lang::JavaScript,
    );
    let body = format!(
        r#"'use strict';
// Nyx dynamic harness — class method (Phase 19 / Track M.1), auto-generated.
{probe}

{mock_http}
{mock_db}
{mock_log}

const payload = (process.env.NYX_PAYLOAD && process.env.NYX_PAYLOAD.length > 0)
    ? process.env.NYX_PAYLOAD
    : (process.env.NYX_PAYLOAD_B64
        ? Buffer.from(process.env.NYX_PAYLOAD_B64, 'base64').toString('utf8')
        : '');

let _entry;
try {{
    _entry = require('./{entry_require_path}');
}} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
}}

const _Cls = _entry[{class:?}] || (_entry.default && _entry.default[{class:?}]) || (typeof _entry.default === 'function' && _entry.default.name === {class:?} ? _entry.default : null);
if (typeof _Cls !== 'function') {{
    process.stderr.write('NYX_CLASS_NOT_FOUND: ' + {class:?} + '\n');
    process.exit(78);
}}

function _nyxBuildReceiver(Cls) {{
    try {{
        return new Cls();
    }} catch (_e) {{
        // Fall back to a single mock-dependency ctor.  The brief allows
        // up to depth-3 dependency stubbing; v1 keeps the chain depth
        // at one and lets the verifier promote precision in a later
        // phase.
        try {{ return new Cls(new MockHttpClient(), new MockDatabaseConnection(), new MockLogger()); }} catch (_e2) {{}}
        try {{ return new Cls(new MockDatabaseConnection()); }} catch (_e3) {{}}
        try {{ return new Cls(new MockHttpClient()); }} catch (_e4) {{}}
        try {{ return new Cls(new MockLogger()); }} catch (_e5) {{}}
        return null;
    }}
}}

const _instance = _nyxBuildReceiver(_Cls);
if (_instance == null) {{
    process.stderr.write('NYX_CLASS_CTOR_FAILED: ' + {class:?} + '\n');
    process.exit(78);
}}

const _m = _instance[{method:?}];
if (typeof _m !== 'function') {{
    process.stderr.write('NYX_METHOD_NOT_FOUND: ' + {method:?} + '\n');
    process.exit(78);
}}

(async () => {{
    try {{
        const _result = await Promise.resolve(_m.call(_instance, payload));
        if (_result != null) process.stdout.write(String(_result) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#,
        class = class,
        method = method,
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: Some(entry_subpath.to_owned()),
    }
}

/// Phase 20 (Track M.2) — message-handler harness for Node.js / TypeScript.
///
/// Imports the entry module, locates the handler function named by
/// `spec.entry_name`, mounts the `NyxSqsLoopback` in-process loopback,
/// and publishes the payload onto `queue` so the handler fires
/// synchronously.  SQS is the only broker Node has a dedicated Phase
/// 20 adapter for (`sqs-node`); the dispatch defaults to it.
fn emit_message_handler(spec: &HarnessSpec, queue: &str, is_typescript: bool) -> HarnessSource {
    let probe = probe_shim();
    let entry_subpath = if is_typescript {
        "entry.ts"
    } else {
        "entry.js"
    };
    let entry_require_path = entry_require_path(entry_subpath);
    let handler = &spec.entry_name;
    let sqs_src = crate::dynamic::stubs::sqs_source(crate::symbol::Lang::JavaScript);
    let publish_marker = crate::dynamic::stubs::SQS_PUBLISH_MARKER;

    let body = format!(
        r#"'use strict';
// Nyx dynamic harness — message handler (Phase 20 / Track M.2).
{probe}

{sqs_src}

const payload = (process.env.NYX_PAYLOAD && process.env.NYX_PAYLOAD.length > 0)
    ? process.env.NYX_PAYLOAD
    : (process.env.NYX_PAYLOAD_B64
        ? Buffer.from(process.env.NYX_PAYLOAD_B64, 'base64').toString('utf8')
        : '');

let _entry;
try {{
    _entry = require('./{entry_require_path}');
}} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
}}

const _handler = _entry[{handler:?}]
    || (_entry.default && _entry.default[{handler:?}])
    || (typeof _entry.default === 'function' && _entry.default.name === {handler:?} ? _entry.default : null);
if (typeof _handler !== 'function') {{
    process.stderr.write('NYX_HANDLER_NOT_FOUND: ' + {handler:?} + '\n');
    process.exit(78);
}}

const _broker = new NyxSqsLoopback();
_broker.subscribe({queue:?}, async (envelope) => {{
    try {{
        // Sink-reachability sentinel — runner's `vuln_fired && sink_hit`
        // gate requires this byte sequence on stdout / stderr.
        process.stdout.write('__NYX_SINK_HIT__\n');
        await Promise.resolve(_handler(envelope));
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}});

(async () => {{
    process.stdout.write({publish_marker:?} + ' ' + {queue:?} + '\n');
    _broker.publish({queue:?}, payload);
}})();
"#,
        handler = handler,
        queue = queue,
        publish_marker = publish_marker,
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: Some(entry_subpath.to_owned()),
    }
}

// ── Phase 21 (Track M.3) — synthetic entry-kind harnesses ─────────────────────

fn nyx_js_preamble(spec: &HarnessSpec, is_typescript: bool) -> (String, String) {
    let probe = probe_shim();
    let entry_subpath = if is_typescript {
        "entry.ts"
    } else {
        "entry.js"
    };
    let require_path = entry_require_path(entry_subpath);
    let preamble = format!(
        r#"'use strict';
{probe}

const payload = (process.env.NYX_PAYLOAD && process.env.NYX_PAYLOAD.length > 0)
    ? process.env.NYX_PAYLOAD
    : (process.env.NYX_PAYLOAD_B64
        ? Buffer.from(process.env.NYX_PAYLOAD_B64, 'base64').toString('utf8')
        : '');

let _entry;
try {{
    _entry = require('./{require_path}');
}} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
}}

function _nyxResolve(name) {{
    const _h = _entry[name]
        || (_entry.default && _entry.default[name])
        || (typeof _entry.default === 'function' && _entry.default.name === name ? _entry.default : null);
    return (typeof _h === 'function') ? _h : null;
}}

process.stdout.write('__NYX_SINK_HIT__\n');
"#,
        probe = probe,
        require_path = require_path,
    );
    let _ = spec;
    (preamble, entry_subpath.to_owned())
}

fn emit_scheduled_job(
    spec: &HarnessSpec,
    schedule: Option<&str>,
    is_typescript: bool,
) -> HarnessSource {
    let (preamble, entry_subpath) = nyx_js_preamble(spec, is_typescript);
    let handler = &spec.entry_name;
    let schedule_repr = schedule.unwrap_or("<unscheduled>");
    let body = format!(
        r#"{preamble}
// Phase 21 (Track M.3) — scheduled job.
process.stdout.write('__NYX_SCHEDULED_JOB__: ' + {schedule:?} + '\n');
const _h = _nyxResolve({handler:?});
if (_h == null) {{
    process.stderr.write('NYX_HANDLER_NOT_FOUND: ' + {handler:?} + '\n');
    process.exit(78);
}}
(async () => {{
    try {{
        const _result = await Promise.resolve(_h(payload));
        if (_result != null) process.stdout.write(String(_result) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#,
        preamble = preamble,
        handler = handler,
        schedule = schedule_repr,
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: Some(entry_subpath),
    }
}

fn emit_graphql_resolver(
    spec: &HarnessSpec,
    type_name: &str,
    field: &str,
    is_typescript: bool,
) -> HarnessSource {
    let (preamble, entry_subpath) = nyx_js_preamble(spec, is_typescript);
    let handler = &spec.entry_name;
    let body = format!(
        r#"{preamble}
// Phase 21 (Track M.3) — GraphQL resolver.
process.stdout.write('__NYX_GRAPHQL_RESOLVER__: ' + {type_name:?} + '.' + {field:?} + '\n');
const _h = _nyxResolve({handler:?});
if (_h == null) {{
    process.stderr.write('NYX_RESOLVER_NOT_FOUND: ' + {handler:?} + '\n');
    process.exit(78);
}}
(async () => {{
    try {{
        // Apollo resolver shape: (parent, args, context, info).
        const _info = {{ fieldName: {field:?}, parentType: {type_name:?} }};
        const _result = await Promise.resolve(_h(null, {{ id: payload, input: payload }}, {{}}, _info));
        if (_result != null) process.stdout.write(String(_result) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#,
        preamble = preamble,
        handler = handler,
        type_name = type_name,
        field = field,
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: Some(entry_subpath),
    }
}

fn emit_websocket_handler(spec: &HarnessSpec, path: &str, is_typescript: bool) -> HarnessSource {
    let (preamble, entry_subpath) = nyx_js_preamble(spec, is_typescript);
    let handler = &spec.entry_name;
    let body = format!(
        r#"{preamble}
// Phase 21 (Track M.3) — WebSocket handler.
process.stdout.write('__NYX_WEBSOCKET__: ' + {path:?} + '\n');
const _h = _nyxResolve({handler:?});
if (_h == null) {{
    process.stderr.write('NYX_HANDLER_NOT_FOUND: ' + {handler:?} + '\n');
    process.exit(78);
}}
(async () => {{
    try {{
        // ws library: handler(message); socket.io: handler(socket, data).
        let _result;
        try {{
            _result = await Promise.resolve(_h(payload));
        }} catch (e1) {{
            if (e1 && e1.constructor && e1.constructor.name === 'TypeError') {{
                _result = await Promise.resolve(_h({{ id: 'nyx-sock' }}, payload));
            }} else {{
                throw e1;
            }}
        }}
        if (_result != null) process.stdout.write(String(_result) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#,
        preamble = preamble,
        handler = handler,
        path = path,
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: Some(entry_subpath),
    }
}

fn emit_middleware(spec: &HarnessSpec, name: &str, is_typescript: bool) -> HarnessSource {
    let (preamble, entry_subpath) = nyx_js_preamble(spec, is_typescript);
    let handler = &spec.entry_name;
    let body = format!(
        r#"{preamble}
// Phase 21 (Track M.3) — middleware.
process.stdout.write('__NYX_MIDDLEWARE__: ' + {name:?} + '\n');
const _h = _nyxResolve({handler:?});
if (_h == null) {{
    process.stderr.write('NYX_HANDLER_NOT_FOUND: ' + {handler:?} + '\n');
    process.exit(78);
}}
const _req = {{ body: payload, query: {{ q: payload }}, params: {{ id: payload }}, headers: {{}}, method: 'POST', url: '/nyx' }};
const _res = {{ statusCode: 200, headers: {{}}, end: function(d){{ if (d != null) process.stdout.write(String(d) + '\n'); }}, setHeader: function(k, v){{ this.headers[k] = v; }} }};
(async () => {{
    try {{
        const _result = await Promise.resolve(_h(_req, _res, function(_e){{ if (_e) process.stderr.write('NYX_NEXT_ERR: ' + _e + '\n'); }}));
        if (_result != null) process.stdout.write(String(_result) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#,
        preamble = preamble,
        handler = handler,
        name = name,
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: Some(entry_subpath),
    }
}

fn emit_migration(spec: &HarnessSpec, version: Option<&str>, is_typescript: bool) -> HarnessSource {
    let (preamble, entry_subpath) = nyx_js_preamble(spec, is_typescript);
    let handler = &spec.entry_name;
    let version_repr = version.unwrap_or("<no-version>");
    let body = format!(
        r#"{preamble}
// Phase 21 (Track M.3) — migration.
process.stdout.write('__NYX_MIGRATION__: ' + {version:?} + '\n');
const _h = _nyxResolve({handler:?});
if (_h == null) {{
    process.stderr.write('NYX_HANDLER_NOT_FOUND: ' + {handler:?} + '\n');
    process.exit(78);
}}
// Synthetic queryInterface for sequelize-style up/down(queryInterface, Sequelize).
const _qi = {{
    createTable: async function(){{}},
    addColumn: async function(){{}},
    dropTable: async function(){{}},
    removeColumn: async function(){{}},
    bulkInsert: async function(){{}},
    sequelize: {{ query: async function(){{}} }},
}};
const _prisma = {{
    $executeRaw: async function(){{}},
    $executeRawUnsafe: async function(s){{ if (s) process.stdout.write('NYX_PRISMA_SQL: ' + s + '\n'); }},
    $queryRaw: async function(){{}},
    $queryRawUnsafe: async function(){{}},
}};
(async () => {{
    try {{
        let _result;
        // Try the sequelize shape first (queryInterface, Sequelize).
        try {{
            _result = await Promise.resolve(_h(_qi, {{}}));
        }} catch (e1) {{
            // Prisma / raw migration shape — pass payload.
            try {{
                _result = await Promise.resolve(_h(payload));
            }} catch (e2) {{
                _result = await Promise.resolve(_h());
            }}
        }}
        if (_result != null) process.stdout.write(String(_result) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#,
        preamble = preamble,
        handler = handler,
        version = version_repr,
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: Some(entry_subpath),
    }
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
//
// Routes `NYX_PAYLOAD` through the real `handlebars` npm package's
// `compile(payload)({{}})` call.  Handlebars does not evaluate
// arithmetic in `{{{{ ... }}}}` blocks by itself; the corpus vuln
// payload `{{{{multiply 7 7}}}}` invokes a registered `multiply`
// helper which returns `49`.  The benign control `7*7` has no
// `{{{{` / `}}}}` markers so the engine echoes it verbatim.
{shim}

const Handlebars = require('handlebars');

Handlebars.registerHelper('multiply', function (a, b) {{
  return String(Number(a) * Number(b));
}});
Handlebars.registerHelper('add', function (a, b) {{
  return String(Number(a) + Number(b));
}});

function nyxHandlebarsRender(payload) {{
  try {{
    return Handlebars.compile(payload)({{}});
  }} catch (e) {{
    return '<handlebars-error:' + (e && e.name ? e.name : 'Error') + '>';
  }}
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
        extra_files: vec![(
            "package.json".to_owned(),
            r#"{"name":"nyx-ssti-handlebars-harness","private":true,"dependencies":{"handlebars":"^4.7.8"}}
"#
            .to_owned(),
        )],
        entry_subpath: None,
    }
}

/// Phase 07 — Track J.5 XPath-injection harness for Node
/// (`xpath` npm package's `select`).
///
/// Reads `NYX_PAYLOAD`, splices it into a `//user[@name='<payload>']`
/// expression, counts matching `<user>` nodes against the canonical
/// staged document, and writes a `ProbeKind::Xpath { nodes_returned }`
/// probe whose `n` is the count returned.  Mirrors the synthetic-
/// harness pattern used by Phase 03 / 04 / 05 / 06.
pub fn emit_xpath_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let corpus_filename = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_FILENAME;
    let corpus_xml = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_XML;
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_stem = derive_js_entry_stem(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_real_xpath = entry_source.contains("require('xpath')")
        || entry_source.contains("require(\"xpath\")");

    let body = format!(
        r#"// Nyx dynamic harness — XPATH_INJECTION xpath.select (Phase 07 / Track J.5).
{shim}

const NYX_XPATH_USERS = ['alice', 'bob', 'carol'];

function nyxXpathSelect(expr) {{
  const needle = "//user[@name=";
  if (!expr.startsWith(needle)) return 0;
  const rest = expr.slice(needle.length);
  if (!rest.endsWith("]")) return 0;
  const predicate = rest.slice(0, -1);

  let m = predicate.match(/^'([^']*)'(.*)$/);
  if (m) {{
    const literal = m[1];
    const tail = m[2].trim();
    if (tail === '' || tail === ']') {{
      return NYX_XPATH_USERS.filter((u) => u === literal).length;
    }}
    if (/^or\s+/i.test(tail)) {{
      return NYX_XPATH_USERS.length;
    }}
  }}
  m = predicate.match(/^"([^"]*)"\s*$/);
  if (m) {{
    const literal = m[1];
    return NYX_XPATH_USERS.filter((u) => u === literal).length;
  }}
  if (/^concat\(/i.test(predicate)) {{
    const parts = [...predicate.matchAll(/'([^']*)'/g)].map((x) => x[1]);
    let joined = parts.filter((p) => p !== ',"').join('');
    joined = joined.split(",\"'\",").join("'");
    return NYX_XPATH_USERS.filter((u) => u === joined).length;
  }}
  return NYX_XPATH_USERS.length;
}}

function nyxXpathViaFixture(payload) {{
  // Phase 07 tier-(a): require the fixture and call its
  // `{entry_name}` so the real `xpath.select` (or other XPath evaluator
  // the fixture chooses) runs against the staged corpus document.
  // Returns the node count, or `null` when the require / lookup / call
  // fails (e.g. the `xpath` npm package is not installed on the host)
  // so the caller can fall back to the inline matcher.
  let _entry;
  try {{
    _entry = require('./{entry_stem}');
  }} catch (e) {{
    return null;
  }}
  const fn = _entry && (typeof _entry === 'function' ? _entry : _entry['{entry_name}']);
  if (typeof fn !== 'function') return null;
  let result;
  try {{
    result = fn(payload);
  }} catch (e) {{
    // Malformed XPath / parse error / etc. — treat as 0-node return
    // so a benign fixture that rejects the payload stays NotConfirmed.
    return 0;
  }}
  if (result == null) return 0;
  if (typeof result.length === 'number') return result.length;
  return 0;
}}

function nyxXpathProbe(expr, nodesReturned) {{
  const p = process.env.NYX_PROBE_PATH;
  if (!p) return;
  const rec = {{
    sink_callee: 'xpath.select',
    args: [{{ kind: 'String', value: expr }}],
    captured_at_ns: Number(process.hrtime.bigint()),
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{ kind: 'Xpath', nodes_returned: nodesReturned }},
    witness: __nyx_witness('xpath.select', [expr]),
  }};
  try {{
    require('fs').appendFileSync(p, JSON.stringify(rec) + '\n');
  }} catch (e) {{
    // best-effort
  }}
}}

const payload = process.env.NYX_PAYLOAD || '';
const expr = "//user[@name='" + payload + "']";
let nodes = nyxXpathViaFixture(payload);
if (nodes === null) {{
  nodes = nyxXpathSelect(expr);
}}
nyxXpathProbe(expr, nodes);
console.log('__NYX_SINK_HIT__');
console.log(JSON.stringify({{ expr: expr, nodes_returned: nodes }}));
"#
    );
    let mut extra_files = vec![(corpus_filename.to_owned(), corpus_xml.to_owned())];
    if uses_real_xpath {
        extra_files.push(("package.json".to_owned(), package_json_xpath()));
        extra_files.push((
            "package-lock.json".to_owned(),
            package_lock_skeleton("nyx-harness-xpath"),
        ));
    }
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files,
        entry_subpath: None,
    }
}

/// Map an entry file path like `tests/.../vuln.js` to the basename
/// (without extension) the harness will `require('./<stem>')`.  Falls
/// back to `"vuln"` so the harness still attempts a require when the
/// path is unusable (the inline matcher fires when the require fails).
fn derive_js_entry_stem(entry_file: &str) -> String {
    PathBuf::from(entry_file)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| "vuln".to_owned())
}

/// `package.json` bundling `xpath` + `@xmldom/xmldom` so the JS XPath
/// fixtures can `require('xpath')` / `require('@xmldom/xmldom')` from
/// the harness workdir.  Mirrors `package_json_for` but pins two deps.
fn package_json_xpath() -> String {
    "{\n  \"name\": \"nyx-harness-xpath\",\n  \"version\": \"0.0.0\",\n  \"private\": true,\n  \"dependencies\": {\n    \"xpath\": \"^0.0.34\",\n    \"@xmldom/xmldom\": \"^0.8.10\"\n  }\n}\n".to_owned()
}

/// Phase 08 — Track J.6 header-injection harness for Node
/// (`http.ServerResponse#setHeader`).
///
/// Reads `NYX_PAYLOAD` and, when the fixture imports `http` or
/// `express`, routes through tier-(a): `require('./<entry-stem>')` +
/// look up the named entry function + call it with a permissive `res`
/// mock whose `setHeader` records every `(name, value)` pair the
/// fixture writes verbatim *before* Node's CRLF validator would
/// reject the call.  Mirrors the Python werkzeug-Headers monkey-patch
/// at `src/dynamic/lang/python.rs::emit_header_injection_harness` and
/// the Java permissive servlet stub at
/// `src/dynamic/lang/java_servlet_stubs.rs::http_servlet_response`.
/// Falls back to the inline `nyxHeaderProbe('Set-Cookie', payload)`
/// synthetic probe when the fixture does not import a Node response
/// writer or when the tier-(a) call fails (require throws, entry
/// function missing, etc.).
pub fn emit_header_injection_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_stem = derive_js_entry_stem(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_node_writer = entry_source.contains("require('http')")
        || entry_source.contains("require(\"http\")")
        || entry_source.contains("require('express')")
        || entry_source.contains("require(\"express\")")
        || entry_source.contains("from 'http'")
        || entry_source.contains("from \"http\"")
        || entry_source.contains("from 'express'")
        || entry_source.contains("from \"express\"");

    let via_fixture = if uses_node_writer {
        format!(
            r#"function nyxHeaderViaFixture(payload) {{
  // Phase 08 tier-(a): require the fixture, call its `{entry_name}`
  // with a permissive `res` mock whose `setHeader` records every
  // `(name, value)` pair verbatim *before* Node's CRLF validator
  // would reject the call.  Returns the captured pairs as an array
  // of `[name, value]` tuples, or `null` when the require / lookup /
  // call fails so the caller can fall back to the inline probe.
  const captured = [];
  const res = {{
    setHeader(name, value) {{
      try {{
        captured.push([String(name), String(value)]);
      }} catch (e) {{
        // ignore — captor is best-effort
      }}
    }},
    getHeader(_name) {{ return undefined; }},
    removeHeader(_name) {{}},
    writeHead(_status, headers) {{
      if (headers && typeof headers === 'object') {{
        for (const k of Object.keys(headers)) {{
          try {{ captured.push([String(k), String(headers[k])]); }} catch (e) {{}}
        }}
      }}
    }},
    end() {{}},
    statusCode: 200,
  }};
  let _entry;
  try {{
    _entry = require('./{entry_stem}');
  }} catch (e) {{
    return null;
  }}
  const fn = _entry && (typeof _entry === 'function' ? _entry : _entry['{entry_name}']);
  if (typeof fn !== 'function') return null;
  // Phase 08 fixtures use `run(res, value)`; the Express open-redirect
  // shape is `run(req, res, value)`.  Try the two-arg path first, then
  // fall through to the three-arg path so an Express handler that
  // calls `res.setHeader` also lands.
  try {{
    fn(res, payload);
  }} catch (e) {{
    captured.length = 0;
    try {{
      fn({{ headers: {{}}, method: 'GET', url: '/' }}, res, payload);
    }} catch (e2) {{
      // both signatures threw — return whatever was captured before
      // the throw, or null when nothing landed
    }}
  }}
  return captured;
}}

"#
        )
    } else {
        String::new()
    };

    let invoke_via_fixture = if uses_node_writer {
        "const captured = nyxHeaderViaFixture(payload);\nif (Array.isArray(captured) && captured.length > 0) {\n  for (const [hname, hvalue] of captured) {\n    nyxHeaderProbe(hname, hvalue);\n  }\n  console.log('__NYX_SINK_HIT__');\n  console.log(JSON.stringify({ headers: captured.map(([n, v]) => [n, v]) }));\n} else {\n  // Synthetic fallback — fixture import / call failed.\n  const name = 'Set-Cookie';\n  const value = payload;\n  nyxHeaderProbe(name, value);\n  console.log('__NYX_SINK_HIT__');\n  console.log(JSON.stringify({ name: name, value: value }));\n}\n"
    } else {
        "const name = 'Set-Cookie';\nconst value = payload;\nnyxHeaderProbe(name, value);\nconsole.log('__NYX_SINK_HIT__');\nconsole.log(JSON.stringify({ name: name, value: value }));\n"
    };

    let body = format!(
        r#"// Nyx dynamic harness — HEADER_INJECTION http.ServerResponse#setHeader (Phase 08 / Track J.6).
{shim}

function nyxHeaderProbe(name, value) {{
  const p = process.env.NYX_PROBE_PATH;
  if (!p) return;
  const rec = {{
    sink_callee: 'http.ServerResponse#setHeader',
    args: [
      {{ kind: 'String', value: name }},
      {{ kind: 'String', value: value }},
    ],
    captured_at_ns: Number(process.hrtime.bigint()),
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{ kind: 'HeaderEmit', name: name, value: value }},
    witness: __nyx_witness('http.ServerResponse#setHeader', [name, value]),
  }};
  try {{
    require('fs').appendFileSync(p, JSON.stringify(rec) + '\n');
  }} catch (e) {{
    // best-effort
  }}
}}

{via_fixture}const payload = process.env.NYX_PAYLOAD || '';
{invoke_via_fixture}"#
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 09 — Track J.7 open-redirect harness for Node (Express
/// `res.redirect`).
///
/// Reads `NYX_PAYLOAD` and, when the fixture imports `express` or
/// `http`, routes through tier-(a): `require('./<entry-stem>')` +
/// look up the named entry function + call it with a permissive `res`
/// mock whose `redirect` / `setHeader('Location', …)` record the
/// bound URL.  Mirrors the Python tier-(a) at
/// `src/dynamic/lang/python.rs::emit_open_redirect_harness`: call the
/// fixture, read the Location header off the response.  Falls back to
/// the inline synthetic probe (`nyxRedirectProbe(payload, …)`) when
/// the fixture does not import a Node response writer or when the
/// tier-(a) call fails.
pub fn emit_open_redirect_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_stem = derive_js_entry_stem(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_node_writer = entry_source.contains("require('http')")
        || entry_source.contains("require(\"http\")")
        || entry_source.contains("require('express')")
        || entry_source.contains("require(\"express\")")
        || entry_source.contains("from 'http'")
        || entry_source.contains("from \"http\"")
        || entry_source.contains("from 'express'")
        || entry_source.contains("from \"express\"");

    let via_fixture = if uses_node_writer {
        format!(
            r#"function nyxRedirectViaFixture(payload) {{
  // Phase 09 tier-(a): require the fixture, call its `{entry_name}`
  // with a permissive `res` mock whose `redirect` / `setHeader` both
  // record the bound `Location:` URL.  Returns `[location, host]` or
  // `null` when the require / lookup / call fails so the caller can
  // fall back to the inline synthetic probe.
  let location = null;
  const recordLocation = (value) => {{
    if (location === null && value !== undefined && value !== null) {{
      location = String(value);
    }}
  }};
  const res = {{
    redirect(...args) {{
      // Express signatures: redirect(url) | redirect(status, url).
      if (args.length === 1) {{
        recordLocation(args[0]);
      }} else if (args.length >= 2) {{
        recordLocation(args[1]);
      }}
    }},
    setHeader(name, value) {{
      if (String(name).toLowerCase() === 'location') {{
        recordLocation(value);
      }}
    }},
    set(name, value) {{
      if (String(name).toLowerCase() === 'location') {{
        recordLocation(value);
      }}
    }},
    location(value) {{
      recordLocation(value);
    }},
    writeHead(_status, headers) {{
      if (headers && typeof headers === 'object') {{
        for (const k of Object.keys(headers)) {{
          if (k.toLowerCase() === 'location') {{
            recordLocation(headers[k]);
          }}
        }}
      }}
    }},
    end() {{}},
    statusCode: 200,
  }};
  const req = {{ headers: {{}}, method: 'GET', url: '/' }};
  let _entry;
  try {{
    _entry = require('./{entry_stem}');
  }} catch (e) {{
    return null;
  }}
  const fn = _entry && (typeof _entry === 'function' ? _entry : _entry['{entry_name}']);
  if (typeof fn !== 'function') return null;
  // Phase 09 fixtures use `run(req, res, value)` (Express handler
  // signature).  Try the three-arg path first; if it throws try the
  // two-arg shape `(res, value)` so a fixture without an explicit
  // `req` parameter still lands.
  try {{
    fn(req, res, payload);
  }} catch (e) {{
    try {{
      fn(res, payload);
    }} catch (e2) {{
      // both signatures threw — return whatever was captured before
      // the throw, or null when nothing landed
    }}
  }}
  if (location === null) return null;
  return [location, 'example.com'];
}}

"#
        )
    } else {
        String::new()
    };

    let invoke_via_fixture = if uses_node_writer {
        "const captured = nyxRedirectViaFixture(payload);\nif (Array.isArray(captured)) {\n  const [location, requestHost] = captured;\n  nyxRedirectProbe(location, requestHost);\n  console.log('__NYX_SINK_HIT__');\n  console.log(JSON.stringify({ location: location, request_host: requestHost }));\n} else {\n  // Synthetic fallback — fixture import / call failed.\n  const requestHost = 'example.com';\n  const location = payload;\n  nyxRedirectProbe(location, requestHost);\n  console.log('__NYX_SINK_HIT__');\n  console.log(JSON.stringify({ location: location, request_host: requestHost }));\n}\n"
    } else {
        "const requestHost = 'example.com';\nconst location = payload;\nnyxRedirectProbe(location, requestHost);\nconsole.log('__NYX_SINK_HIT__');\nconsole.log(JSON.stringify({ location: location, request_host: requestHost }));\n"
    };

    let body = format!(
        r#"// Nyx dynamic harness — OPEN_REDIRECT res.redirect (Phase 09 / Track J.7).
{shim}

function nyxRedirectProbe(location, requestHost) {{
  const p = process.env.NYX_PROBE_PATH;
  if (!p) return;
  const rec = {{
    sink_callee: 'res.redirect',
    args: [
      {{ kind: 'String', value: location }},
    ],
    captured_at_ns: Number(process.hrtime.bigint()),
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{ kind: 'Redirect', location: location, request_host: requestHost }},
    witness: __nyx_witness('res.redirect', [location]),
  }};
  try {{
    require('fs').appendFileSync(p, JSON.stringify(rec) + '\n');
  }} catch (e) {{
    // best-effort
  }}
}}

{via_fixture}const payload = process.env.NYX_PAYLOAD || '';
{invoke_via_fixture}"#
    );
    HarnessSource {
        source: body,
        filename: "harness.js".to_owned(),
        command: vec!["node".to_owned(), "harness.js".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 10 — Track J.8 prototype-pollution harness for Node
/// (`lodash.merge` / `Object.assign` / `JSON.parse`-then-deep-assign).
///
/// Reads `NYX_PAYLOAD`, parses it as JSON, and walks the parsed
/// object into a synthetic vanilla target via a naive recursive
/// deep-merge.  Before the sink runs the harness installs a
/// `Proxy`-style setter trap on `Object.prototype.__nyx_canary`
/// (modelled as an accessor property — the only working canary
/// mechanism for the language's shared `Object.prototype` —
/// configured to forward every write through a `Proxy`-style
/// observation).  When the merge walks an attacker-controlled
/// `__proto__` key into the target, the deep-merge dereferences
/// `target.__proto__` (which is `Object.prototype`) and the
/// canary's setter records a `ProbeKind::PrototypePollution { property:
/// "__nyx_canary", value }` probe.  A benign payload whose JSON
/// literal has no `__proto__` key — or a fixture that constructs
/// its target via `Object.create(null)` — leaves the prototype
/// chain untouched and emits no probe.
pub fn emit_prototype_pollution_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"// Nyx dynamic harness — PROTOTYPE_POLLUTION canary trap (Phase 10 / Track J.8).
{shim}

const NYX_PP_CANARY = '__nyx_canary';

function nyxPrototypePollutionProbe(value) {{
  const p = process.env.NYX_PROBE_PATH;
  if (!p) return;
  const rec = {{
    sink_callee: '__nyx_pp_canary_set',
    args: [
      {{ kind: 'String', value: NYX_PP_CANARY }},
      {{ kind: 'String', value: String(value) }},
    ],
    captured_at_ns: Number(process.hrtime.bigint()),
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{
      kind: 'PrototypePollution',
      property: NYX_PP_CANARY,
      value: String(value),
    }},
    witness: __nyx_witness('__nyx_pp_canary_set', [NYX_PP_CANARY, value]),
  }};
  try {{
    require('fs').appendFileSync(p, JSON.stringify(rec) + '\n');
  }} catch (e) {{
    // best-effort
  }}
}}

(function installPrototypeCanary() {{
  // Proxy-style setter trap on Object.prototype.__nyx_canary.  A
  // real `new Proxy(Object.prototype, ...)` cannot replace
  // Object.prototype itself, so the trap is modelled as an
  // accessor property routed through the same observation hook the
  // ProbeKind::PrototypePollution probe expects.
  //
  // The setter receiver (`this`) is the actual write target after
  // prototype-chain resolution.  Only a write that *landed on
  // Object.prototype itself* is true prototype pollution; a write
  // to a child object's `__nyx_canary` would also reach this setter
  // via prototype lookup but does not pollute the shared prototype,
  // so we ignore it.  Without this guard a benign deep-merge of
  // `{{data: {{__nyx_canary: ...}}}}` into a plain `{{}}` target
  // would falsely fire the probe.
  let _canaryStorage;
  Object.defineProperty(Object.prototype, NYX_PP_CANARY, {{
    configurable: true,
    enumerable: false,
    set: function (v) {{
      _canaryStorage = v;
      if (this === Object.prototype) {{
        nyxPrototypePollutionProbe(v);
      }}
    }},
    get: function () {{
      return _canaryStorage;
    }},
  }});
}})();

function nyxDeepMerge(target, source) {{
  if (source === null || typeof source !== 'object') return target;
  for (const key of Object.keys(source)) {{
    const sv = source[key];
    if (sv !== null && typeof sv === 'object') {{
      if (target[key] === null || typeof target[key] !== 'object') {{
        target[key] = {{}};
      }}
      nyxDeepMerge(target[key], sv);
    }} else {{
      target[key] = sv;
    }}
  }}
  return target;
}}

const payload = process.env.NYX_PAYLOAD || '';
let parsed;
try {{
  parsed = JSON.parse(payload);
}} catch (e) {{
  parsed = {{}};
}}
const target = {{}};
try {{
  nyxDeepMerge(target, parsed);
}} catch (e) {{
  // Naive merge may throw on weird inputs; the canary observation
  // already wrote any probe before the throw.
}}
console.log('__NYX_SINK_HIT__');
console.log(JSON.stringify({{
  canary_present: Object.prototype.hasOwnProperty(NYX_PP_CANARY),
}}));
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
        JsShape::Fastify => emit_fastify(spec),
        JsShape::Nest => emit_nest(spec),
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
let _resolveResponded;
const _responded = new Promise(function (r) {{ _resolveResponded = r; }});
const _markResponded = function () {{
    if (_resolveResponded) {{
        const _r = _resolveResponded;
        _resolveResponded = null;
        _r();
    }}
}};
const _res = {{
    statusCode: 200,
    headers: {{}},
    status: function (c) {{ this.statusCode = c; return this; }},
    set: function (k, v) {{ this.headers[k] = v; return this; }},
    setHeader: function (k, v) {{ this.headers[k] = v; }},
    send: function (b) {{ _captured += String(b == null ? '' : b); _markResponded(); return this; }},
    end: function (b) {{ if (b != null) _captured += String(b); _markResponded(); return this; }},
    json: function (o) {{ _captured += JSON.stringify(o); _markResponded(); return this; }},
    write: function (b) {{ _captured += String(b == null ? '' : b); return this; }},
}};
(async () => {{
    try {{
        const _result = _handler(_req, _res, function () {{}});
        if (_result && typeof _result.then === 'function') await _result;
        // Handlers that finish via an async callback (e.g. child_process.exec)
        // populate _captured after the handler return. Wait up to 3s for a
        // res.send / res.end / res.json call before flushing stdout.
        await Promise.race([_responded, new Promise(function (r) {{ setTimeout(r, 3000); }})]);
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
let _resolveResponded;
const _responded = new Promise(function (r) {{ _resolveResponded = r; }});
const _markResponded = function () {{
    if (_resolveResponded) {{
        const _r = _resolveResponded;
        _resolveResponded = null;
        _r();
    }}
}};
const _ctx = {{
    method: {method:?},
    query: {{}},
    request: {{ body: {{}}, query: {{}}, header: {{}} }},
    params: {{}},
    headers: {{}},
    _body: '',
    status: 200,
    set: function (k, v) {{ this.headers[k] = v; }},
}};
Object.defineProperty(_ctx, 'body', {{
    get: function () {{ return this._body; }},
    set: function (v) {{ this._body = v; _markResponded(); }},
    enumerable: true,
    configurable: true,
}});
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
        // Wait up to 3s for an async ctx.body assignment (e.g. from a
        // child_process.exec callback) before flushing stdout.
        await Promise.race([_responded, new Promise(function (r) {{ setTimeout(r, 3000); }})]);
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
let _resolveResponded;
const _responded = new Promise(function (r) {{ _resolveResponded = r; }});
const _markResponded = function () {{
    if (_resolveResponded) {{
        const _r = _resolveResponded;
        _resolveResponded = null;
        _r();
    }}
}};
const _res = {{
    statusCode: 200,
    headers: {{}},
    status: function (c) {{ this.statusCode = c; return this; }},
    setHeader: function (k, v) {{ this.headers[k] = v; }},
    send: function (b) {{ _captured += String(b == null ? '' : b); _markResponded(); return this; }},
    end: function (b) {{ if (b != null) _captured += String(b); _markResponded(); return this; }},
    json: function (o) {{ _captured += JSON.stringify(o); _markResponded(); return this; }},
    write: function (b) {{ _captured += String(b == null ? '' : b); return this; }},
}};
(async () => {{
    try {{
        const _result = _handler(_req, _res);
        if (_result && typeof _result.then === 'function') await _result;
        // Handlers that finish via an async callback (e.g. child_process.exec)
        // populate _captured after the handler return. Wait up to 3s for a
        // res.send / res.end / res.json call before flushing stdout.
        await Promise.race([_responded, new Promise(function (r) {{ setTimeout(r, 3000); }})]);
        process.stdout.write(_captured + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#
    )
}

/// Phase 13 — Track L.11 Fastify harness.
///
/// Loads the entry's `app` export (the configured Fastify instance)
/// and replays the spec's request through Fastify's built-in
/// [`light-my-request`](https://github.com/fastify/light-my-request)
/// equivalent — `app.inject({ method, url, query, payload, headers })`.
/// No external `supertest` dep is required because `inject` ships in
/// Fastify core.
fn emit_fastify(spec: &HarnessSpec) -> String {
    let (method, payload_key, body_kind) = resolve_http_payload(&spec.payload_slot);
    let route_path = framework_route_path(spec);
    format!(
        r#"// Shape: Fastify route — boot via app.inject() (light-my-request equivalent).
let _app = _entry.app || _entry.default || _entry;
const _kind = {body_kind:?};
const _payload_key = {payload_key:?};
const _method = {method:?};
let _path = {route_path:?};
let _query;
let _bodyArg = undefined;
let _headers = {{}};
if (_kind === 'query') {{
    _query = {{}};
    _query[_payload_key] = payload;
}} else if (_kind === 'body') {{
    _bodyArg = payload;
    _headers['content-type'] = 'application/json';
}} else if (_kind === 'env') {{
    process.env[_payload_key] = payload;
}} else if (_kind === 'param') {{
    _path = '/' + encodeURIComponent(payload);
}}
(async () => {{
    try {{
        // Fastify plugin route table: entry exports `async (instance, opts) => ...`
        // rather than an already-built instance.  Wrap the plugin in a fresh
        // Fastify instance via `.register()` so `.inject()` is available.
        if (typeof _app === 'function' && typeof _app.inject !== 'function') {{
            const _fastifyModule = require('fastify');
            const _fastifyFactory = _fastifyModule.default || _fastifyModule;
            const _wrapped = _fastifyFactory();
            await _wrapped.register(_app);
            _app = _wrapped;
        }}
        if (!_app || typeof _app.inject !== 'function') {{
            process.stderr.write('NYX_FASTIFY_APP_NOT_FOUND\n');
            process.exit(78);
        }}
        if (typeof _app.ready === 'function') await _app.ready();
        const _injectOpts = {{ method: _method, url: _path, headers: _headers }};
        if (_query) _injectOpts.query = _query;
        if (_bodyArg !== undefined) _injectOpts.payload = _bodyArg;
        const _res = await _app.inject(_injectOpts);
        process.stdout.write(String(_res.body == null ? '' : _res.body) + '\n');
    }} catch (e) {{
        process.stderr.write('NYX_EXCEPTION: ' + (e.constructor ? e.constructor.name : 'Error') + ': ' + e.message + '\n');
    }}
}})();
"#
    )
}

/// Phase 13 — Track L.11 NestJS harness.
///
/// Loads the entry's exported controller class (`_entry.Controller`
/// / `_entry.default`), mounts it via
/// `Test.createTestingModule({controllers:[Controller]}).compile()`,
/// boots the Nest application, and replays the spec's request through
/// `supertest(app.getHttpServer())`.  Falls back to `_entry.app`
/// (already-built Nest app instance) when the fixture pre-mounts
/// itself.  The `supertest` dep is bundled by `extra_files_for_shape`.
fn emit_nest(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (method, payload_key, body_kind) = resolve_http_payload(&spec.payload_slot);
    let method_lower = method.to_ascii_lowercase();
    let route_path = framework_route_path(spec);
    format!(
        r#"// Shape: NestJS controller — boot via Test.createTestingModule + supertest.
require('reflect-metadata');
let _supertest;
try {{
    _supertest = require('supertest');
}} catch (e) {{
    process.stderr.write('NYX_SUPERTEST_MISSING: ' + e.message + '\n');
    process.exit(79);
}}
let _NestTesting;
try {{
    _NestTesting = require('@nestjs/testing');
}} catch (e) {{
    process.stderr.write('NYX_NESTJS_TESTING_MISSING: ' + e.message + '\n');
    process.exit(79);
}}
const _kind = {body_kind:?};
const _payload_key = {payload_key:?};
const _method_lc = {method_lower:?};
const _entry_name = {entry_fn:?};
let _path = {route_path:?};
if (_kind === 'env') {{
    process.env[_payload_key] = payload;
}} else if (_kind === 'param') {{
    _path = '/' + encodeURIComponent(payload);
}}
(async () => {{
    try {{
        let _app = _entry.app || (_entry.default && _entry.default.app);
        if (!_app) {{
            // Prefer an exported @Module class — real Nest projects
            // mount controllers via their enclosing module's
            // `imports:[...]`, not by passing the controller class
            // directly.  Match any export whose name ends in `Module`
            // (the canonical Nest convention).
            const _moduleEntry = Object.entries(_entry).find(([k, v]) =>
                typeof v === 'function' && /Module$/.test(k)
            );
            if (_moduleEntry) {{
                const _moduleClass = _moduleEntry[1];
                const _module = await _NestTesting.Test
                    .createTestingModule({{ imports: [_moduleClass] }})
                    .compile();
                _app = _module.createNestApplication();
                await _app.init();
            }} else {{
                // Locate a controller class — first @Controller / class export.
                const _candidate = _entry[_entry_name]
                    || _entry.default
                    || _entry.AppController
                    || _entry.Controller
                    || Object.values(_entry).find((v) => typeof v === 'function');
                if (typeof _candidate !== 'function') {{
                    process.stderr.write('NYX_NEST_CONTROLLER_NOT_FOUND\n');
                    process.exit(78);
                }}
                const _module = await _NestTesting.Test
                    .createTestingModule({{ controllers: [_candidate] }})
                    .compile();
                _app = _module.createNestApplication();
                await _app.init();
            }}
        }}
        const _server = (typeof _app.getHttpServer === 'function')
            ? _app.getHttpServer()
            : _app;
        const _agent = _supertest(_server);
        let _req = _agent[_method_lc](_path);
        if (_kind === 'query') {{
            const _q = {{}};
            _q[_payload_key] = payload;
            _req = _req.query(_q);
        }} else if (_kind === 'body') {{
            _req = _req.set('content-type', 'application/json').send(payload);
        }}
        const _res = await _req;
        process.stdout.write(String(_res.text == null ? '' : _res.text) + '\n');
        if (typeof _app.close === 'function') await _app.close();
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

/// Pull the route path string from the spec's stamped framework
/// binding, falling back to `"/"` when no adapter has bound (legacy
/// pre-stamp path) or when the binding does not carry an HTTP route.
///
/// Used by the Fastify (`app.inject`) and Nest (`supertest`) emitters,
/// both of which actually route requests through the framework's
/// matcher rather than calling the handler directly — Express, Koa,
/// and Next.js dispatch the handler bare so the path is irrelevant.
fn framework_route_path(spec: &HarnessSpec) -> String {
    spec.framework
        .as_ref()
        .and_then(|f| f.route.as_ref())
        .map(|r| r.path.clone())
        .unwrap_or_else(|| "/".to_owned())
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

/// Supported entry kinds for both JS + TS after Phase 21.
pub const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::HttpRoute,
    EntryKindTag::CliSubcommand,
    EntryKindTag::LibraryApi,
    EntryKindTag::ClassMethod,
    EntryKindTag::MessageHandler,
    EntryKindTag::ScheduledJob,
    EntryKindTag::GraphQLResolver,
    EntryKindTag::WebSocket,
    EntryKindTag::Middleware,
    EntryKindTag::Migration,
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
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn detect_express_via_require() {
        let src = "const express = require('express');\nfunction ping(req, res) {}";
        let spec = make_spec(
            EntryKind::Function,
            "ping",
            PayloadSlot::QueryParam("host".into()),
        );
        assert_eq!(JsShape::detect(&spec, src), JsShape::Express);
    }

    #[test]
    fn detect_koa_via_require() {
        let src = "const Koa = require('koa');\nasync function ping(ctx) {}";
        let spec = make_spec(
            EntryKind::Function,
            "ping",
            PayloadSlot::QueryParam("host".into()),
        );
        assert_eq!(JsShape::detect(&spec, src), JsShape::Koa);
    }

    #[test]
    fn detect_next_via_marker() {
        let src = "// nyx-shape: next\nmodule.exports = async function handler(req, res) {};";
        let spec = make_spec(
            EntryKind::HttpRoute,
            "handler",
            PayloadSlot::QueryParam("host".into()),
        );
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
        let src =
            "// nyx-shape: esm-default\nexport default function runPing(host) { return host; }";
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
        let spec = make_spec(
            EntryKind::HttpRoute,
            "ping",
            PayloadSlot::QueryParam("host".into()),
        );
        let src = generate_for_shape(&spec, JsShape::Express, "entry.js");
        assert!(src.contains("Express handler"));
        assert!(src.contains("_req.query[_payload_key] = payload"));
    }

    #[test]
    fn emit_koa_awaits_middleware() {
        let spec = make_spec(
            EntryKind::HttpRoute,
            "ping",
            PayloadSlot::QueryParam("host".into()),
        );
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

    fn make_spec_with_route(
        kind: EntryKind,
        name: &str,
        slot: PayloadSlot,
        route_path: &str,
    ) -> HarnessSpec {
        use crate::dynamic::framework::{FrameworkBinding, HttpMethod, RouteShape};
        let mut spec = make_spec(kind, name, slot);
        spec.framework = Some(FrameworkBinding {
            adapter: "test-adapter".into(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape {
                method: HttpMethod::GET,
                path: route_path.into(),
            }),
            request_params: vec![],
            response_writer: None,
            middleware: vec![],
        });
        spec
    }

    #[test]
    fn framework_route_path_defaults_to_slash_when_unstamped() {
        let spec = make_spec(
            EntryKind::HttpRoute,
            "runCmd",
            PayloadSlot::QueryParam("cmd".into()),
        );
        assert_eq!(framework_route_path(&spec), "/");
    }

    #[test]
    fn framework_route_path_returns_binding_path_when_stamped() {
        let spec = make_spec_with_route(
            EntryKind::HttpRoute,
            "runCmd",
            PayloadSlot::QueryParam("cmd".into()),
            "/run",
        );
        assert_eq!(framework_route_path(&spec), "/run");
    }

    #[test]
    fn emit_fastify_threads_route_path_from_binding() {
        let spec = make_spec_with_route(
            EntryKind::HttpRoute,
            "runCmd",
            PayloadSlot::QueryParam("cmd".into()),
            "/run",
        );
        let src = generate_for_shape(&spec, JsShape::Fastify, "entry.js");
        assert!(
            src.contains("let _path = \"/run\""),
            "fastify emit must use route path from binding: {src}",
        );
    }

    #[test]
    fn emit_fastify_falls_back_to_slash_when_unstamped() {
        let spec = make_spec(
            EntryKind::HttpRoute,
            "runCmd",
            PayloadSlot::QueryParam("cmd".into()),
        );
        let src = generate_for_shape(&spec, JsShape::Fastify, "entry.js");
        assert!(
            src.contains("let _path = \"/\""),
            "fastify emit must default to / when no binding: {src}",
        );
    }

    #[test]
    fn emit_nest_threads_route_path_from_binding() {
        let spec = make_spec_with_route(
            EntryKind::HttpRoute,
            "runCmd",
            PayloadSlot::QueryParam("cmd".into()),
            "/run",
        );
        let src = generate_for_shape(&spec, JsShape::Nest, "entry.js");
        assert!(
            src.contains("let _path = \"/run\""),
            "nest emit must use route path from binding: {src}",
        );
    }

    #[test]
    fn extra_files_for_express_has_package_json() {
        let extras = extra_files_for_shape(JsShape::Express);
        assert!(
            extras
                .iter()
                .any(|(p, c)| p == "package.json" && c.contains("express"))
        );
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

    fn make_xpath_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(EntryKind::Function, entry_name, PayloadSlot::Param(0));
        spec.expected_cap = Cap::XPATH_INJECTION;
        spec.entry_file = entry_file.into();
        spec.entry_name = entry_name.into();
        spec
    }

    #[test]
    fn emit_xpath_harness_drives_fixture_through_real_xpath_when_imported() {
        let dir = std::env::temp_dir().join("nyx_phase07_js_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "const xpath = require('xpath');\n\
             function run(name) { return []; }\n\
             module.exports = { run };\n",
        )
        .unwrap();
        let h = emit_xpath_harness(&make_xpath_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("function nyxXpathViaFixture(payload)"),
            "tier-(a) harness must define nyxXpathViaFixture: {}",
            h.source
        );
        assert!(
            h.source.contains("require('./vuln')"),
            "tier-(a) harness must require the staged fixture: {}",
            h.source
        );
        assert!(
            h.source.contains("_entry['run']"),
            "tier-(a) harness must look up the named entry function: {}",
            h.source
        );
        assert!(
            h.source.contains("if (typeof result.length === 'number') return result.length;"),
            "tier-(a) harness must count nodes via the returned array's .length: {}",
            h.source
        );
        assert!(
            h.source.contains("nodes = nyxXpathSelect(expr);"),
            "tier-(a) harness must preserve the inline matcher as a fallback: {}",
            h.source
        );
        assert!(
            h.extra_files
                .iter()
                .any(|(p, c)| p == "package.json" && c.contains("\"xpath\"")),
            "tier-(a) harness must stage a package.json with the xpath dep",
        );
        assert!(
            h.extra_files
                .iter()
                .any(|(p, c)| p == "package.json" && c.contains("@xmldom/xmldom")),
            "tier-(a) harness must stage a package.json with the xmldom dep",
        );
        assert!(
            h.extra_files
                .iter()
                .any(|(p, _)| p == "package-lock.json"),
            "tier-(a) harness must stage a package-lock.json",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_xpath_harness_falls_back_to_inline_matcher_without_xpath_require() {
        let dir = std::env::temp_dir().join("nyx_phase07_js_test_no_xpath_require");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "function run(name) { return []; }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_xpath_harness(&make_xpath_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.extra_files.iter().any(|(p, _)| p == "package.json"),
            "fallback path must not stage a package.json (xpath dep would be unused)",
        );
        assert!(
            !h.extra_files
                .iter()
                .any(|(p, _)| p == "package-lock.json"),
            "fallback path must not stage a package-lock.json",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_xpath_harness_derives_entry_stem_from_entry_file() {
        let dir = std::env::temp_dir().join("nyx_phase07_js_test_stem_derive");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("benign.js");
        std::fs::write(
            &entry,
            "const xpath = require('xpath');\nfunction run(name) { return []; }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_xpath_harness(&make_xpath_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("require('./benign')"),
            "harness must require the staged fixture by its file_stem: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_header_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(EntryKind::Function, entry_name, PayloadSlot::Param(0));
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = entry_file.into();
        spec.entry_name = entry_name.into();
        spec
    }

    fn make_redirect_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(EntryKind::Function, entry_name, PayloadSlot::Param(0));
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = entry_file.into();
        spec.entry_name = entry_name.into();
        spec
    }

    #[test]
    fn emit_header_injection_harness_routes_through_fixture_when_http_required() {
        let dir = std::env::temp_dir().join("nyx_phase08_js_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "const http = require('http');\nfunction run(res, value) { res.setHeader('Set-Cookie', value); }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(
            entry.to_str().unwrap(),
            "run",
        ));
        assert!(
            h.source.contains("function nyxHeaderViaFixture(payload)"),
            "tier-(a) harness must define nyxHeaderViaFixture: {}",
            h.source
        );
        assert!(
            h.source.contains("require('./vuln')"),
            "tier-(a) harness must require the staged fixture: {}",
            h.source
        );
        assert!(
            h.source.contains("_entry['run']"),
            "tier-(a) harness must look up the named entry function: {}",
            h.source
        );
        assert!(
            h.source.contains("captured.push([String(name), String(value)])"),
            "tier-(a) harness must record (name, value) pairs verbatim: {}",
            h.source
        );
        assert!(
            h.source.contains("Synthetic fallback"),
            "tier-(a) harness must preserve the inline probe as a fallback: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_falls_back_when_http_not_required() {
        let dir = std::env::temp_dir().join("nyx_phase08_js_test_no_http");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "function run(res, value) { res.setHeader('Set-Cookie', value); }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(
            entry.to_str().unwrap(),
            "run",
        ));
        assert!(
            !h.source.contains("function nyxHeaderViaFixture(payload)"),
            "fallback path must not emit the tier-(a) helper: {}",
            h.source
        );
        assert!(
            h.source.contains("const name = 'Set-Cookie';"),
            "fallback path must emit the inline synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_derives_entry_stem_from_entry_file() {
        let dir = std::env::temp_dir().join("nyx_phase08_js_test_stem_derive");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("benign.js");
        std::fs::write(
            &entry,
            "const http = require('http');\nfunction run(res, value) { res.setHeader('Set-Cookie', encodeURIComponent(value)); }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(
            entry.to_str().unwrap(),
            "run",
        ));
        assert!(
            h.source.contains("require('./benign')"),
            "tier-(a) harness must require the staged fixture by its file_stem: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_routes_through_fixture_when_express_required() {
        let dir = std::env::temp_dir().join("nyx_phase09_js_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "const express = require('express');\nfunction run(req, res, value) { res.redirect(value); }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(
            entry.to_str().unwrap(),
            "run",
        ));
        assert!(
            h.source.contains("function nyxRedirectViaFixture(payload)"),
            "tier-(a) harness must define nyxRedirectViaFixture: {}",
            h.source
        );
        assert!(
            h.source.contains("require('./vuln')"),
            "tier-(a) harness must require the staged fixture: {}",
            h.source
        );
        assert!(
            h.source.contains("_entry['run']"),
            "tier-(a) harness must look up the named entry function: {}",
            h.source
        );
        assert!(
            h.source.contains("redirect(...args)"),
            "tier-(a) harness must define a res.redirect captor: {}",
            h.source
        );
        assert!(
            h.source.contains("if (String(name).toLowerCase() === 'location')"),
            "tier-(a) harness must also capture setHeader('Location', …) writes: {}",
            h.source
        );
        assert!(
            h.source.contains("Synthetic fallback"),
            "tier-(a) harness must preserve the inline probe as a fallback: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_falls_back_when_express_not_required() {
        let dir = std::env::temp_dir().join("nyx_phase09_js_test_no_express");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "function run(req, res, value) { res.redirect(value); }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(
            entry.to_str().unwrap(),
            "run",
        ));
        assert!(
            !h.source.contains("function nyxRedirectViaFixture(payload)"),
            "fallback path must not emit the tier-(a) helper: {}",
            h.source
        );
        assert!(
            h.source.contains("const requestHost = 'example.com';"),
            "fallback path must emit the inline synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
