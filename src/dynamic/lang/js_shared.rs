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

    if let Some(adapter) = env.framework_adapter.as_deref() {
        for dep in crate::dynamic::framework::runtime_deps::deps_for_adapter(adapter).node_packages
        {
            if seen.insert(dep.name.to_owned()) {
                deps.push((dep.name.to_owned(), dep.version));
            }
        }
    }
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

    // Phase 11 (Track J.9): JSON_PARSE depth-bomb short-circuit.  The
    // synthetic harness monkey-patches `JSON.parse`, walks the parsed
    // value iteratively to record maximum nesting depth, emits a
    // `ProbeKind::JsonParse { depth, excessive_depth }` record, then
    // routes the payload through the fixture entry.  RangeError-style
    // V8 stack-exhaustion paths emit `JsonParse { depth: 0,
    // excessive_depth: true }` so the predicate still fires when the
    // engine rejects the input outright.
    if spec.expected_cap == crate::labels::Cap::JSON_PARSE {
        return Ok(emit_json_parse_harness(spec));
    }

    // Phase 11 (Track J.9): UNAUTHORIZED_ID harness.  Imports the
    // fixture via CommonJS, invokes the named entry with the payload
    // as `owner_id`, and emits a `ProbeKind::IdorAccess` record only
    // when the fixture returned a non-null/undefined record.  Mirrors
    // the Python / Ruby emitters.
    if spec.expected_cap == crate::labels::Cap::UNAUTHORIZED_ID {
        return Ok(emit_unauthorized_id_harness(spec));
    }

    // Phase 11 (Track J.9): DATA_EXFIL harness.  Monkey-patches
    // `require('http').request` / `.get`, the same on `https`, and
    // `global.fetch` so any outbound HTTP request the fixture
    // initiates is captured before the wire I/O.  Mirrors the
    // Python `urlopen` patch and the Ruby `Net::HTTP` open-class
    // shim.
    if spec.expected_cap == crate::labels::Cap::DATA_EXFIL {
        return Ok(emit_data_exfil_harness(spec));
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
/// recursively instantiates same-module constructor dependencies up to
/// depth 3, falls back to known mock dependencies, and invokes
/// `instance[method](payload)`.
fn emit_class_method(
    _spec: &HarnessSpec,
    class: &str,
    method: &str,
    _is_typescript: bool,
) -> HarnessSource {
    let probe = probe_shim();
    let entry_subpath = "entry.js";
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

function _nyxExportedClass(name) {{
    if (!name) return null;
    if (_entry && typeof _entry[name] === 'function') return _entry[name];
    if (_entry && _entry.default && typeof _entry.default[name] === 'function') return _entry.default[name];
    if (_entry && typeof _entry.default === 'function' && _entry.default.name === name) return _entry.default;
    return null;
}}

function _nyxConstructorParams(Cls) {{
    let src = '';
    try {{ src = Function.prototype.toString.call(Cls); }} catch (_e) {{ return []; }}
    const match = src.match(/constructor\s*\(([^)]*)\)/m);
    if (!match) return [];
    return match[1]
        .split(',')
        .map((part) => part.replace(/\/\*.*?\*\//g, '').replace(/\/\/.*$/g, '').trim())
        .map((part) => part.replace(/^(\.\.\.)/, '').split('=')[0].trim())
        .filter(Boolean);
}}

function _nyxClassNameFromParam(paramName) {{
    const cleaned = String(paramName || '')
        .replace(/^[^A-Za-z_$]+/, '')
        .replace(/[^A-Za-z0-9_$]+(.)/g, (_m, ch) => String(ch).toUpperCase());
    if (!cleaned) return '';
    return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}}

function _nyxKnownMock(paramName) {{
    const lc = String(paramName || '').toLowerCase();
    if (lc.includes('http') || lc.includes('client')) return new MockHttpClient();
    if (lc.includes('database') || lc.includes('db')) return new MockDatabaseConnection();
    if (lc.includes('logger') || lc.includes('log')) return new MockLogger();
    return null;
}}

function _nyxBuildDependency(paramName, depth, seen) {{
    const depName = _nyxClassNameFromParam(paramName);
    const Dep = _nyxExportedClass(depName);
    if (typeof Dep === 'function') {{
        const built = _nyxBuildReceiver(Dep, depth - 1, new Set(seen));
        if (built != null) return built;
    }}
    return _nyxKnownMock(paramName);
}}

function _nyxBuildReceiver(Cls, depth = 3, seen = new Set()) {{
    if (typeof Cls !== 'function') return null;
    const clsName = Cls.name || '<anonymous>';
    if (depth < 0 || seen.has(clsName)) return null;
    seen.add(clsName);
    const params = _nyxConstructorParams(Cls);
    if (params.length > 0) {{
        const deps = params.map((name) => _nyxBuildDependency(name, depth, seen));
        if (deps.every((dep) => dep != null)) {{
            try {{ return new Cls(...deps); }} catch (_e) {{}}
        }}
    }}
    try {{ return new Cls(); }} catch (_e) {{}}
    try {{ return new Cls(new MockHttpClient(), new MockDatabaseConnection(), new MockLogger()); }} catch (_e2) {{}}
    try {{ return new Cls(new MockDatabaseConnection()); }} catch (_e3) {{}}
    try {{ return new Cls(new MockHttpClient()); }} catch (_e4) {{}}
    try {{ return new Cls(new MockLogger()); }} catch (_e5) {{}}
    return null;
}}

const _instance = _nyxBuildReceiver(_Cls, 3);
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
        process.stdout.write('__NYX_SINK_HIT__\n');
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
function _nyxRecordBrokerPublish(envName, destination, body) {{
    const path = process.env[envName] || '';
    if (!path) return;
    try {{
        require('fs').appendFileSync(
            path,
            String(destination).replace(/\t/g, ' ') + '\t' + String(body) + '\n',
            'utf8'
        );
    }} catch (_) {{}}
}}
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
    _nyxRecordBrokerPublish('NYX_SQS_LOG', {queue:?}, payload);
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
        extra_files: message_handler_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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
    let entry_stem = derive_js_entry_stem(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };

    let body = format!(
        r#"// Nyx dynamic harness — XPATH_INJECTION xpath.select (Phase 07 / Track J.5).
{shim}

function nyxXpathViaFixture(payload) {{
  // Phase 07 tier-(a): require the fixture and call its
  // `{entry_name}` so the real `xpath.select` (or other XPath evaluator
  // the fixture chooses) runs against the staged corpus document.  A
  // missing `xpath` host install is the only structural reason the
  // require fails; in that case we emit the conventional
  // `NYX_IMPORT_ERROR:` stderr marker plus `process.exit(77)` so the
  // runner maps the outcome to `RunError::BuildFailed` and the e2e
  // SKIP branch fires.
  let _entry;
  try {{
    _entry = require('./{entry_stem}');
  }} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
  }}
  const fn = _entry && (typeof _entry === 'function' ? _entry : _entry['{entry_name}']);
  if (typeof fn !== 'function') {{
    throw new Error("Phase 07 XPath harness: entry function '{entry_name}' not found in fixture module './{entry_stem}'");
  }}
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
const nodes = nyxXpathViaFixture(payload);
console.log('__NYX_XPATH_TIER_A__');
nyxXpathProbe(expr, nodes);
console.log('__NYX_SINK_HIT__');
console.log(JSON.stringify({{ expr: expr, nodes_returned: nodes }}));
"#
    );
    let extra_files = vec![
        (corpus_filename.to_owned(), corpus_xml.to_owned()),
        ("package.json".to_owned(), package_json_xpath()),
        (
            "package-lock.json".to_owned(),
            package_lock_skeleton("nyx-harness-xpath"),
        ),
    ];
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
    // Phase 08 tier-(b): a fixture that uses `net.createServer` writes
    // bytes straight to the response socket via `socket.write`, bypassing
    // every framework-level CRLF validator (Node's
    // `http.ServerResponse#setHeader` / Express / axum / Tomcat all
    // strip CRLF before write).  The harness boots the server on a
    // loopback port and captures the raw response-header block as a
    // `ProbeKind::HeaderWireFrame` probe.  Mirrors the Python tier-(b)
    // at `src/dynamic/lang/python.rs::emit_header_injection_harness`.
    let uses_raw_socket = entry_source.contains("net.createServer")
        || entry_source.contains("require('net')")
        || entry_source.contains("require(\"net\")")
        || entry_source.contains("from 'net'")
        || entry_source.contains("from \"net\"");

    let wire_frame_via_fixture = if uses_raw_socket {
        format!(
            r#"async function nyxWireFrameViaFixture(payload) {{
  // Phase 08 tier-(b): boot the fixture's net.Server on 127.0.0.1:0,
  // issue one raw-socket GET, read the bytes the handler wrote to the
  // response socket up to the CRLF-CRLF boundary.  Returns the captured
  // header-block bytes on success, or `null` on import / boot failure so
  // the caller can fall back to the inline synthetic probe.
  const _net = require('net');
  let mod;
  try {{
    mod = require('./{entry_stem}');
  }} catch (e) {{
    return null;
  }}
  if (!mod || typeof mod.createServer !== 'function' || typeof mod.setCookieValue !== 'function') {{
    return null;
  }}
  try {{
    if (Buffer.isBuffer(payload)) {{
      mod.setCookieValue(payload);
    }} else {{
      mod.setCookieValue(Buffer.from(String(payload), 'utf8'));
    }}
  }} catch (e) {{
    return null;
  }}
  let server;
  try {{
    server = mod.createServer();
  }} catch (e) {{
    return nyxFallbackWireFrame(payload);
  }}
  const listenPort = await new Promise((resolve) => {{
    server.once('error', () => resolve(null));
    server.listen(0, '127.0.0.1', () => {{
      const addr = server.address();
      resolve(addr && typeof addr === 'object' ? addr.port : null);
    }});
  }});
  if (listenPort === null) {{
    try {{ server.close(); }} catch (e) {{}}
    return nyxFallbackWireFrame(payload);
  }}
  let raw = Buffer.alloc(0);
  await new Promise((resolve) => {{
    const client = _net.createConnection({{ host: '127.0.0.1', port: listenPort }}, () => {{
      try {{
        client.write('GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n');
      }} catch (e) {{}}
    }});
    const timer = setTimeout(() => {{
      try {{ client.destroy(); }} catch (e) {{}}
      resolve();
    }}, 5000);
    client.on('data', (chunk) => {{
      raw = Buffer.concat([raw, chunk]);
      if (raw.length >= 65536 || raw.indexOf('\r\n\r\n') !== -1) {{
        try {{ client.end(); }} catch (e) {{}}
      }}
    }});
    client.on('end', () => {{ clearTimeout(timer); resolve(); }});
    client.on('error', () => {{ clearTimeout(timer); resolve(); }});
    client.on('close', () => {{ clearTimeout(timer); resolve(); }});
  }});
  try {{ server.close(); }} catch (e) {{}}
  if (raw.length === 0) {{
    return nyxFallbackWireFrame(payload);
  }}
  const sep = raw.indexOf('\r\n\r\n');
  if (sep === -1) {{
    return raw;
  }}
  return raw.subarray(0, sep);
}}

function nyxFallbackWireFrame(payload) {{
  const cookie = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const body = Buffer.from('ok\n', 'utf8');
  return Buffer.concat([
    Buffer.from('HTTP/1.0 200 OK\r\n', 'binary'),
    Buffer.from('Content-Length: ' + body.length + '\r\n', 'binary'),
    Buffer.from('Set-Cookie: ', 'binary'),
    cookie,
  ]);
}}

function nyxWireFrameProbe(rawBytes) {{
  const p = process.env.NYX_PROBE_PATH;
  if (!p) return;
  const rec = {{
    sink_callee: 'net.Server.socket.write',
    args: [],
    captured_at_ns: Number(process.hrtime.bigint()),
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{ kind: 'HeaderWireFrame', raw_bytes: Array.from(rawBytes) }},
    witness: __nyx_witness('net.Server.socket.write', []),
  }};
  try {{
    require('fs').appendFileSync(p, JSON.stringify(rec) + '\n');
  }} catch (e) {{
    // best-effort
  }}
}}

"#
        )
    } else {
        String::new()
    };

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

    // Phase 08 tier-(b): when the fixture imports `net.createServer`, run
    // the wire-frame branch first (async IIFE awaits the loopback round
    // trip).  When it succeeds, emit a `HeaderWireFrame` probe plus a
    // derived `HeaderEmit` per Set-Cookie line and exit.  When it returns
    // null (require/boot failure), fall through to the existing sync
    // tier-(a) / synthetic path so the harness still produces some
    // signal.
    let body = if uses_raw_socket {
        format!(
            r#"// Nyx dynamic harness — HEADER_INJECTION net.Server raw-socket wire-frame (Phase 08 / Track J.6).
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
    kind: {{ kind: 'HeaderEmit', name: name, value: value, protocol: 'in-process' }},
    witness: __nyx_witness('http.ServerResponse#setHeader', [name, value]),
  }};
  try {{
    require('fs').appendFileSync(p, JSON.stringify(rec) + '\n');
  }} catch (e) {{
    // best-effort
  }}
}}

{wire_frame_via_fixture}(async () => {{
  const payload = process.env.NYX_PAYLOAD || '';
  const rawBytes = await nyxWireFrameViaFixture(payload);
  if (rawBytes !== null && rawBytes !== undefined) {{
    nyxWireFrameProbe(rawBytes);
    // Also emit a HeaderEmit record per Set-Cookie line so the tier-(a)
    // HeaderInjected predicate fires on the same payload that trips
    // HeaderSmuggledInWire.  The wire-frame branch is the source of
    // truth; the HeaderEmit records are derived from the same captured
    // bytes.
    const headerText = rawBytes.toString('binary');
    for (const line of headerText.split('\r\n')) {{
      const sep = line.indexOf(': ');
      if (sep < 0) continue;
      const hname = line.slice(0, sep);
      if (hname.toLowerCase() !== 'set-cookie') continue;
      const hvalue = line.slice(sep + 2);
      nyxHeaderProbe(hname, hvalue);
    }}
    console.log('__NYX_SINK_HIT__');
    console.log(JSON.stringify({{ wire_frame_len: rawBytes.length }}));
    return;
  }}
  // Synthetic fallback — wire-frame branch did not produce bytes.
  const name = 'Set-Cookie';
  const value = payload;
  nyxHeaderProbe(name, value);
  console.log('__NYX_SINK_HIT__');
  console.log(JSON.stringify({{ name: name, value: value }}));
}})();
"#
        )
    } else {
        format!(
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
    kind: {{ kind: 'HeaderEmit', name: name, value: value, protocol: 'in-process' }},
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
        )
    };
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
        "const captured = nyxRedirectViaFixture(payload);\nif (Array.isArray(captured)) {\n  const [location, requestHost] = captured;\n  nyxRedirectProbe(location, requestHost);\n  nyxFollowLocation(location);\n  console.log('__NYX_SINK_HIT__');\n  console.log(JSON.stringify({ location: location, request_host: requestHost }));\n} else {\n  // Synthetic fallback — fixture import / call failed.\n  const requestHost = 'example.com';\n  const location = payload;\n  nyxRedirectProbe(location, requestHost);\n  nyxFollowLocation(location);\n  console.log('__NYX_SINK_HIT__');\n  console.log(JSON.stringify({ location: location, request_host: requestHost }));\n}\n"
    } else {
        "const requestHost = 'example.com';\nconst location = payload;\nnyxRedirectProbe(location, requestHost);\nnyxFollowLocation(location);\nconsole.log('__NYX_SINK_HIT__');\nconsole.log(JSON.stringify({ location: location, request_host: requestHost }));\n"
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

// Phase 09 OOB closure: when the captured Location is a fully-qualified
// loopback URL, follow it with a real GET so the OOB listener records
// the per-finding nonce.  Skips non-loopback hosts (no real network egress)
// and any non-HTTP scheme.  Best-effort: failures do not propagate, the
// listener may still have observed the connect before the read errored.
function nyxFollowLocation(location) {{
  if (!location || typeof location !== 'string') return;
  const lower = location.toLowerCase();
  if (!(lower.startsWith('http://127.0.0.1')
        || lower.startsWith('http://localhost')
        || lower.startsWith('http://host-gateway'))) {{
    return;
  }}
  try {{
    const http = require('http');
    const req = http.get(location, {{ timeout: 2000 }}, (res) => {{
      res.resume();
    }});
    req.on('error', () => {{}});
    req.on('timeout', () => {{ try {{ req.destroy(); }} catch (e) {{}} }});
  }} catch (e) {{
    // best-effort OOB fetch
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

// Phase 10 sink: route the parsed payload through the real
// `lodash.merge` pinned at lodash 4.17.4.  Lodash hardened `_.merge`
// against the `__proto__` key starting in 4.17.5 (well before the
// official CVE-2018-16487 fix at 4.17.11 which targeted `_.set` /
// `_.setWith`), so the canary only fires against <= 4.17.4.  The
// staged `package.json` pins this version exactly; `prepare_node`
// resolves the dep via `npm install` before the harness runs.
// Exercising the real merge implementation (vs the hand-rolled
// `nyxDeepMerge` that previously stood in) covers lodash's actual
// recursion / cycle / array-vs-object decision shape so a future
// fixture that hits a patched range can be added without re-shaping
// the harness.
const _lodashMerge = require('lodash').merge;

const payload = process.env.NYX_PAYLOAD || '';
let parsed;
try {{
  parsed = JSON.parse(payload);
}} catch (e) {{
  parsed = {{}};
}}
const target = {{}};
try {{
  _lodashMerge(target, parsed);
}} catch (e) {{
  // lodash.merge can throw on weird inputs; the canary observation
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
        extra_files: vec![(
            "package.json".to_owned(),
            r#"{"name":"nyx-prototype-pollution-harness","private":true,"dependencies":{"lodash":"4.17.4"}}
"#
            .to_owned(),
        )],
        entry_subpath: None,
    }
}

/// Phase 11 (Track J.9) — JSON_PARSE depth-bomb harness for Node.
///
/// Monkey-patches `JSON.parse` with a wrapper that calls the original
/// parser, walks the resulting value iteratively (no recursion stack)
/// to compute maximum nesting depth, emits a
/// `ProbeKind::JsonParse { depth, excessive_depth }` record, then
/// returns the parsed value verbatim.  A `RangeError` raised by V8 on
/// excessively-deep input is caught and converted into a
/// `JsonParse { depth: 0, excessive_depth: true }` probe before the
/// error is re-thrown — matching the Python harness's
/// `RecursionError` handling.
///
/// Mirrors `crate::dynamic::lang::python::emit_json_parse_harness`.
pub fn emit_json_parse_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_stem = derive_js_entry_stem(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"// Nyx dynamic harness — JSON_PARSE depth checks (Phase 11 / Track J.9).
{shim}

const _NYX_MAX_WALK = 4096;

function _nyx_count_depth(parsed) {{
  let maxDepth = 0;
  const stack = [[parsed, 1]];
  let visited = 0;
  while (stack.length > 0) {{
    const [cur, depth] = stack.pop();
    visited += 1;
    if (visited > _NYX_MAX_WALK) break;
    if (depth > maxDepth) maxDepth = depth;
    if (cur !== null && typeof cur === 'object') {{
      if (Array.isArray(cur)) {{
        for (let i = 0; i < cur.length; i += 1) {{
          stack.push([cur[i], depth + 1]);
        }}
      }} else {{
        for (const k of Object.keys(cur)) {{
          stack.push([cur[k], depth + 1]);
        }}
      }}
    }}
  }}
  return maxDepth;
}}

function _nyx_json_parse_probe(depth, excessive) {{
  const p = process.env.NYX_PROBE_PATH;
  if (!p) return;
  const rec = {{
    sink_callee: 'JSON.parse',
    args: [{{ kind: 'Int', value: depth | 0 }}],
    captured_at_ns: Number(process.hrtime.bigint()),
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{
      kind: 'JsonParse',
      depth: depth | 0,
      excessive_depth: !!excessive,
    }},
    witness: __nyx_witness('JSON.parse', [depth | 0]),
  }};
  try {{
    require('fs').appendFileSync(p, JSON.stringify(rec) + '\n');
  }} catch (e) {{
    // best-effort
  }}
}}

const _nyx_orig_json_parse = JSON.parse;

JSON.parse = function _nyx_json_parse_with_depth(text, reviver) {{
  let parsed;
  try {{
    parsed = _nyx_orig_json_parse(text, reviver);
  }} catch (e) {{
    // V8 raises `RangeError: Maximum call stack size exceeded` on
    // deeply-nested input.  Emit the excessive-depth probe before
    // re-raising so the oracle still fires.
    if (e instanceof RangeError) {{
      _nyx_json_parse_probe(0, true);
    }}
    throw e;
  }}
  const depth = _nyx_count_depth(parsed);
  _nyx_json_parse_probe(depth, depth > 64);
  return parsed;
}};

function _nyx_json_parse_via_fixture(payload) {{
  let _entry;
  try {{
    _entry = require('./{entry_stem}');
  }} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
  }}
  const fn =
    _entry && (typeof _entry === 'function' ? _entry : _entry['{entry_name}']);
  if (typeof fn !== 'function') {{
    return false;
  }}
  try {{
    fn(payload);
  }} catch (e) {{
    // Parser errors / depth-induced throws are expected on the vuln
    // payload; the probe is already emitted.
  }}
  return true;
}}

const payload = process.env.NYX_PAYLOAD || '';
_nyx_json_parse_via_fixture(payload);
console.log('__NYX_SINK_HIT__');
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

/// Phase 11 (Track J.9) — UNAUTHORIZED_ID IDOR harness for Node.js.
///
/// Reads `NYX_PAYLOAD` as the requested `owner_id`, `require`s the
/// fixture file by its basename, and invokes the named entry with the
/// payload.  When the fixture returns a non-`null` / non-`undefined`
/// record (i.e. the data store materialised the row without an
/// authorization check) the harness emits a
/// [`crate::dynamic::probe::ProbeKind::IdorAccess`] probe carrying the
/// hard-coded `caller_id = "alice"` and the payload as `owner_id`.  The
/// [`crate::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
/// predicate fires whenever `caller_id != owner_id`.
///
/// Mirrors `crate::dynamic::lang::python::emit_unauthorized_id_harness`
/// and `crate::dynamic::lang::ruby::emit_unauthorized_id_harness`.
pub fn emit_unauthorized_id_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_stem = derive_js_entry_stem(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"// Nyx dynamic harness — UNAUTHORIZED_ID IDOR boundary (Phase 11 / Track J.9).
{shim}

const _NYX_CALLER_ID = 'alice';

function _nyx_idor_probe(callerId, ownerId) {{
  const rec = {{
    sink_callee: '__nyx_idor_lookup',
    args: [
      {{ kind: 'String', value: String(callerId) }},
      {{ kind: 'String', value: String(ownerId) }},
    ],
    captured_at_ns: Number(process.hrtime.bigint()),
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{
      kind: 'IdorAccess',
      caller_id: String(callerId),
      owner_id: String(ownerId),
    }},
    witness: __nyx_witness('__nyx_idor_lookup', [String(callerId), String(ownerId)]),
  }};
  __nyx_emit(rec);
}}

function _nyx_idor_via_fixture(payload) {{
  let _entry;
  try {{
    _entry = require('./{entry_stem}');
  }} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
  }}
  const fn =
    _entry && (typeof _entry === 'function' ? _entry : _entry['{entry_name}']);
  if (typeof fn !== 'function') {{
    return null;
  }}
  try {{
    return fn(payload);
  }} catch (e) {{
    return null;
  }}
}}

const payload = process.env.NYX_PAYLOAD || '';
const record = _nyx_idor_via_fixture(payload);
const materialised = record !== null && record !== undefined;
if (materialised) {{
  _nyx_idor_probe(_NYX_CALLER_ID, payload);
}}
console.log('__NYX_SINK_HIT__');
console.log(JSON.stringify({{ materialised }}));
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

/// Phase 11 (Track J.9) — DATA_EXFIL outbound-network harness for Node.js.
///
/// Monkey-patches `require('http').request` / `.get`, the matching
/// `https` exports, and `global.fetch` so any outbound HTTP request
/// the fixture initiates is intercepted before the wire I/O.  The
/// host argument is extracted from either an options object
/// (`{{ host, hostname, ... }}`), a URL instance, or a raw URL
/// string; a [`crate::dynamic::probe::ProbeKind::OutboundNetwork`]
/// probe is emitted with the parsed host, then the call returns a
/// benign in-memory stand-in so the fixture's caller never blocks on
/// the network.  The
/// [`crate::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
/// predicate fires when the captured host falls outside the loopback
/// allowlist.
///
/// Mirrors `crate::dynamic::lang::python::emit_data_exfil_harness`
/// and `crate::dynamic::lang::ruby::emit_data_exfil_harness`.
pub fn emit_data_exfil_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_stem = derive_js_entry_stem(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"// Nyx dynamic harness — DATA_EXFIL outbound-host (Phase 11 / Track J.9).
{shim}

const _NYX_http = require('http');
const _NYX_https = require('https');

function _nyx_outbound_probe(host) {{
  const rec = {{
    sink_callee: '__nyx_mock_http',
    args: [{{ kind: 'String', value: String(host) }}],
    captured_at_ns: Number(process.hrtime.bigint()),
    payload_id: process.env.NYX_PAYLOAD_ID || '',
    kind: {{ kind: 'OutboundNetwork', host: String(host) }},
    witness: __nyx_witness('__nyx_mock_http', [String(host)]),
  }};
  __nyx_emit(rec);
}}

function _nyx_extract_host(target) {{
  if (target === null || target === undefined) return '';
  if (typeof target === 'object') {{
    if (typeof target.hostname === 'string' && target.hostname) {{
      return target.hostname;
    }}
    if (typeof target.host === 'string' && target.host) {{
      const idx = target.host.indexOf(':');
      return idx === -1 ? target.host : target.host.slice(0, idx);
    }}
    if (typeof target.href === 'string') {{
      try {{ return new URL(target.href).hostname; }} catch (e) {{ /* fall through */ }}
    }}
  }}
  const raw = String(target);
  try {{ return new URL(raw).hostname; }} catch (e) {{ /* fall through */ }}
  return raw;
}}

class _NyxFakeRequest {{
  on(_event, _cb) {{ return this; }}
  once(_event, _cb) {{ return this; }}
  setHeader() {{}}
  getHeader() {{}}
  removeHeader() {{}}
  write() {{ return true; }}
  end() {{ return this; }}
  abort() {{}}
  destroy() {{}}
  flushHeaders() {{}}
}}

class _NyxFakeResponse {{
  constructor() {{
    this.statusCode = 200;
    this.statusMessage = 'OK';
    this.headers = {{}};
  }}
  on(event, cb) {{
    if (event === 'end' && typeof cb === 'function') {{
      try {{ cb(); }} catch (e) {{ /* swallow */ }}
    }}
    return this;
  }}
  once(event, cb) {{ return this.on(event, cb); }}
  setEncoding() {{}}
  resume() {{}}
  pause() {{}}
}}

function _nyx_request_shim(opts, cb) {{
  const host = _nyx_extract_host(opts);
  _nyx_outbound_probe(host);
  const req = new _NyxFakeRequest();
  if (typeof cb === 'function') {{
    try {{ cb(new _NyxFakeResponse()); }} catch (e) {{ /* swallow */ }}
  }}
  return req;
}}

_NYX_http.request = _nyx_request_shim;
_NYX_http.get = _nyx_request_shim;
_NYX_https.request = _nyx_request_shim;
_NYX_https.get = _nyx_request_shim;

global.fetch = async function _nyx_fetch_shim(input, _init) {{
  const host = _nyx_extract_host(input);
  _nyx_outbound_probe(host);
  return {{
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Map(),
    text: async () => '',
    json: async () => ({{}}),
    arrayBuffer: async () => new ArrayBuffer(0),
  }};
}};

function _nyx_data_exfil_via_fixture(payload) {{
  let _entry;
  try {{
    _entry = require('./{entry_stem}');
  }} catch (e) {{
    process.stderr.write('NYX_IMPORT_ERROR: ' + e.message + '\n');
    process.exit(77);
  }}
  const fn =
    _entry && (typeof _entry === 'function' ? _entry : _entry['{entry_name}']);
  if (typeof fn !== 'function') {{
    return false;
  }}
  try {{
    fn(payload);
  }} catch (e) {{
    // Probe is already emitted if the fixture reached http.request.
  }}
  return true;
}}

const payload = process.env.NYX_PAYLOAD || '';
_nyx_data_exfil_via_fixture(payload);
console.log('__NYX_SINK_HIT__');
console.log(JSON.stringify({{ payload }}));
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

fn message_handler_dependency_files(spec: &HarnessSpec) -> Vec<(String, String)> {
    if spec.expected_cap != crate::labels::Cap::CODE_EXEC {
        return Vec::new();
    }
    let source = read_entry_source(&spec.entry_file);
    let mut deps = js_message_handler_deps(&source);
    if let Some(adapter) = spec.framework.as_ref().map(|b| b.adapter.as_str()) {
        for dep in crate::dynamic::framework::runtime_deps::deps_for_adapter(adapter).node_packages
        {
            if !deps.iter().any(|(name, _)| *name == dep.name) {
                deps.push((dep.name, dep.version));
            }
        }
    }
    if deps.is_empty() {
        return Vec::new();
    }
    deps.sort_by(|a, b| a.0.cmp(b.0));
    vec![
        (
            "package.json".to_owned(),
            package_json_multi("nyx-harness-message-handler", &deps),
        ),
        (
            "package-lock.json".to_owned(),
            package_lock_skeleton("nyx-harness-message-handler"),
        ),
    ]
}

fn framework_dependency_files(spec: &HarnessSpec) -> Vec<(String, String)> {
    if spec.expected_cap != crate::labels::Cap::CODE_EXEC {
        return Vec::new();
    }
    let Some(adapter) = spec.framework.as_ref().map(|b| b.adapter.as_str()) else {
        return Vec::new();
    };
    let mut deps: Vec<(&'static str, &'static str)> =
        crate::dynamic::framework::runtime_deps::deps_for_adapter(adapter)
            .node_packages
            .iter()
            .map(|dep| (dep.name, dep.version))
            .collect();
    if deps.is_empty() {
        return Vec::new();
    }
    deps.sort_by(|a, b| a.0.cmp(b.0));
    deps.dedup_by(|a, b| a.0 == b.0);
    vec![
        (
            "package.json".to_owned(),
            package_json_multi("nyx-harness-framework", &deps),
        ),
        (
            "package-lock.json".to_owned(),
            package_lock_skeleton("nyx-harness-framework"),
        ),
    ]
}

fn js_message_handler_deps(source: &str) -> Vec<(&'static str, &'static str)> {
    let mut deps = Vec::new();
    for raw_line in source.lines() {
        let line = raw_line.trim_start();
        if line.starts_with("//") || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }
        if (line.contains("= require('@aws-sdk/client-sqs')")
            || line.contains("= require(\"@aws-sdk/client-sqs\")")
            || line.starts_with("import ")
                && (line.contains(" from '@aws-sdk/client-sqs'")
                    || line.contains(" from \"@aws-sdk/client-sqs\"")))
            && !deps.iter().any(|(name, _)| *name == "@aws-sdk/client-sqs")
        {
            deps.push(("@aws-sdk/client-sqs", "^3.583.0"));
        }
        if (line.contains("= require('aws-sdk/clients/sqs')")
            || line.contains("= require(\"aws-sdk/clients/sqs\")")
            || line.starts_with("import ")
                && (line.contains(" from 'aws-sdk/clients/sqs'")
                    || line.contains(" from \"aws-sdk/clients/sqs\"")))
            && !deps.iter().any(|(name, _)| *name == "aws-sdk")
        {
            deps.push(("aws-sdk", "^2.1692.0"));
        }
        if (line.contains("= require('sqs-consumer')")
            || line.contains("= require(\"sqs-consumer\")")
            || line.starts_with("import ")
                && (line.contains(" from 'sqs-consumer'")
                    || line.contains(" from \"sqs-consumer\"")))
            && !deps.iter().any(|(name, _)| *name == "sqs-consumer")
        {
            deps.push(("sqs-consumer", "^11.5.0"));
        }
    }
    deps
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
        process.stdout.write('__NYX_SINK_HIT__\n');
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
        process.stdout.write('__NYX_SINK_HIT__\n');
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
        process.stdout.write('__NYX_SINK_HIT__\n');
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
        process.stdout.write('__NYX_SINK_HIT__\n');
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
            route: Some(RouteShape::single(HttpMethod::GET, route_path)),
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
    fn message_handler_deps_ignore_string_markers() {
        let src = r#"
const _markerRequire = "require('sqs-consumer')";
const _markerImport = "@aws-sdk/client-sqs";
"#;
        assert!(js_message_handler_deps(src).is_empty());
    }

    #[test]
    fn message_handler_deps_detect_real_sqs_imports() {
        let src = r#"
const { Consumer } = require('sqs-consumer');
const { SQSClient } = require('@aws-sdk/client-sqs');
const SQS = require('aws-sdk/clients/sqs');
"#;
        let deps = js_message_handler_deps(src);
        assert!(deps.iter().any(|(name, _)| *name == "sqs-consumer"));
        assert!(deps.iter().any(|(name, _)| *name == "@aws-sdk/client-sqs"));
        assert!(deps.iter().any(|(name, _)| *name == "aws-sdk"));
    }

    #[test]
    fn emit_message_handler_stages_package_json_for_hard_imports() {
        let dir = std::env::temp_dir().join("nyx_message_handler_node_deps");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("entry.js");
        std::fs::write(
            &entry,
            "const { Consumer } = require('sqs-consumer');\n\
             function handler(envelope) { return envelope.Body; }\n\
             module.exports = { handler };\n",
        )
        .unwrap();

        let mut spec = make_spec(
            EntryKind::MessageHandler {
                queue: "jobs".to_owned(),
                message_schema: None,
            },
            "handler",
            PayloadSlot::Param(0),
        );
        spec.entry_file = entry.to_string_lossy().into_owned();

        let h = emit(&spec, false).unwrap();
        assert!(
            h.extra_files
                .iter()
                .any(|(p, c)| p == "package.json" && c.contains("sqs-consumer")),
            "message handler must stage package.json for hard broker imports"
        );
        assert!(h.extra_files.iter().any(|(p, _)| p == "package-lock.json"));
        let _ = std::fs::remove_dir_all(&dir);
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
    fn emit_xpath_harness_routes_through_fixture_require() {
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
            h.source
                .contains("if (typeof result.length === 'number') return result.length;"),
            "tier-(a) harness must count nodes via the returned array's .length: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_XPATH_TIER_A__"),
            "harness must emit the tier-(a) stdout marker after the real xpath call: {}",
            h.source
        );
        assert!(
            h.extra_files
                .iter()
                .any(|(p, c)| p == "package.json" && c.contains("\"xpath\"")),
            "harness must always stage a package.json with the xpath dep",
        );
        assert!(
            h.extra_files
                .iter()
                .any(|(p, c)| p == "package.json" && c.contains("@xmldom/xmldom")),
            "harness must always stage a package.json with the xmldom dep",
        );
        assert!(
            h.extra_files.iter().any(|(p, _)| p == "package-lock.json"),
            "harness must always stage a package-lock.json",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_xpath_harness_drops_inline_matcher_fallback() {
        let dir = std::env::temp_dir().join("nyx_phase07_js_test_no_inline_matcher");
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
            !h.source.contains("nyxXpathSelect"),
            "harness must not carry the inline `nyxXpathSelect` matcher; tier-(a) is the only path",
        );
        assert!(
            !h.source.contains("NYX_XPATH_USERS"),
            "harness must not carry the inline `NYX_XPATH_USERS` table; tier-(a) is the only path",
        );
        assert!(
            h.source.contains("NYX_IMPORT_ERROR:") && h.source.contains("process.exit(77)"),
            "harness must emit `NYX_IMPORT_ERROR:` stderr marker + `process.exit(77)` on require failure: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_XPATH_TIER_A__"),
            "harness must emit the tier-(a) stdout marker: {}",
            h.source
        );
        assert!(
            h.extra_files.iter().any(|(p, _)| p == "package.json"),
            "harness must always stage a package.json (real-xpath dep is required, no synthetic-only path)",
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
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
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
            h.source
                .contains("captured.push([String(name), String(value)])"),
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
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
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
    fn emit_header_injection_harness_routes_through_wire_frame_when_net_create_server_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_js_test_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "const net = require('net');\nlet cookieValue = Buffer.alloc(0);\nfunction setCookieValue(v) { cookieValue = Buffer.from(String(v)); }\nfunction createServer() { return net.createServer((s) => { s.write(Buffer.concat([Buffer.from('HTTP/1.0 200 OK\\r\\nSet-Cookie: '), cookieValue, Buffer.from('\\r\\n\\r\\nok')])); s.end(); }); }\nmodule.exports = { setCookieValue, createServer };\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source
                .contains("async function nyxWireFrameViaFixture(payload)"),
            "tier-(b) harness must define the async wire-frame helper: {}",
            h.source
        );
        assert!(
            h.source.contains("require('./vuln')"),
            "tier-(b) harness must require the staged fixture: {}",
            h.source
        );
        assert!(
            h.source.contains("mod.createServer()"),
            "tier-(b) harness must boot the fixture's net.Server: {}",
            h.source
        );
        assert!(
            h.source
                .contains("'GET / HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n'"),
            "tier-(b) harness must issue a raw GET over the client socket: {}",
            h.source
        );
        assert!(
            h.source
                .contains("kind: 'HeaderWireFrame', raw_bytes: Array.from(rawBytes)"),
            "tier-(b) harness must emit a HeaderWireFrame probe carrying the raw header-block bytes: {}",
            h.source
        );
        assert!(
            h.source.contains("wire_frame_len: rawBytes.length"),
            "tier-(b) harness must print the wire_frame_len stdout marker: {}",
            h.source
        );
        assert!(
            h.source
                .contains("if (hname.toLowerCase() !== 'set-cookie')"),
            "tier-(b) harness must derive a HeaderEmit probe per Set-Cookie line: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_drops_wire_frame_branch_when_only_http_required() {
        let dir = std::env::temp_dir().join("nyx_phase08_js_test_no_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "const http = require('http');\nfunction run(res, value) { res.setHeader('Set-Cookie', value); }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("async function nyxWireFrameViaFixture"),
            "http-only harness must not emit the wire-frame helper: {}",
            h.source
        );
        assert!(
            !h.source.contains("HeaderWireFrame"),
            "http-only harness must not emit the HeaderWireFrame probe shape: {}",
            h.source
        );
        assert!(
            !h.source.contains("wire_frame_len"),
            "http-only harness must not emit the wire_frame_len stdout marker: {}",
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
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
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
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
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
            h.source
                .contains("if (String(name).toLowerCase() === 'location')"),
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
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
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

    #[test]
    fn emit_open_redirect_harness_ships_follow_location_helper() {
        let dir = std::env::temp_dir().join("nyx_phase09_js_test_follow_location");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "const express = require('express');\nfunction run(req, res, value) { res.redirect(value); }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("function nyxFollowLocation(location)"),
            "OPEN_REDIRECT harness must declare the nyxFollowLocation helper: {}",
            h.source
        );
        assert!(
            h.source.contains("http.get(location"),
            "follow-location helper must call http.get on the captured URL: {}",
            h.source
        );
        assert!(
            h.source.contains("lower.startsWith('http://127.0.0.1')")
                && h.source.contains("lower.startsWith('http://localhost')")
                && h.source.contains("lower.startsWith('http://host-gateway')"),
            "follow-location helper must gate on loopback host prefixes: {}",
            h.source
        );
        assert!(
            h.source.contains(
                "nyxRedirectProbe(location, requestHost);\n  nyxFollowLocation(location);"
            ),
            "tier-(a) must follow the captured Location after emitting the probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_follows_synthetic_location_in_fallback() {
        let dir = std::env::temp_dir().join("nyx_phase09_js_test_follow_fallback");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.js");
        std::fs::write(
            &entry,
            "function run(req, res, value) { res.redirect(value); }\nmodule.exports = { run };\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("function nyxFollowLocation(location)"),
            "fallback path must still declare nyxFollowLocation: {}",
            h.source
        );
        assert!(
            h.source
                .contains("nyxRedirectProbe(location, requestHost);\nnyxFollowLocation(location);"),
            "fallback path must follow the synthetic location after the probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_json_parse_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(EntryKind::Function, entry_name, PayloadSlot::Param(0));
        spec.expected_cap = Cap::JSON_PARSE;
        spec.entry_file = entry_file.into();
        spec.entry_name = entry_name.into();
        spec
    }

    #[test]
    fn emit_dispatches_to_json_parse_harness_when_cap_is_json_parse() {
        let h = emit(
            &make_json_parse_spec(
                "tests/dynamic_fixtures/json_parse_depth/javascript/vuln.js",
                "run",
            ),
            false,
        )
        .unwrap();
        assert!(
            h.source.contains("_nyx_json_parse_with_depth"),
            "dispatcher must select the JSON_PARSE depth harness: {}",
            h.source
        );
        assert!(
            h.source.contains("kind: 'JsonParse'"),
            "JSON_PARSE harness must emit JsonParse probes",
        );
    }

    #[test]
    fn emit_json_parse_harness_monkey_patches_json_parse() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/javascript/vuln.js",
            "run",
        ));
        assert!(h.source.contains("const _nyx_orig_json_parse = JSON.parse"));
        assert!(
            h.source
                .contains("JSON.parse = function _nyx_json_parse_with_depth")
        );
        assert!(h.source.contains("function _nyx_count_depth(parsed)"));
    }

    #[test]
    fn emit_json_parse_harness_emits_depth_fields() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/javascript/vuln.js",
            "run",
        ));
        assert!(h.source.contains("depth: depth | 0"));
        assert!(h.source.contains("excessive_depth: !!excessive"));
        assert!(h.source.contains("depth > 64"));
        assert!(h.source.contains("__NYX_SINK_HIT__"));
    }

    #[test]
    fn emit_json_parse_harness_handles_range_error() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/javascript/vuln.js",
            "run",
        ));
        assert!(h.source.contains("e instanceof RangeError"));
        assert!(h.source.contains("_nyx_json_parse_probe(0, true)"));
    }

    #[test]
    fn emit_json_parse_harness_routes_through_fixture_require() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/javascript/vuln.js",
            "run",
        ));
        assert!(
            h.source
                .contains("function _nyx_json_parse_via_fixture(payload)")
        );
        assert!(h.source.contains("require('./vuln')"));
        assert!(h.source.contains("_entry['run']"));
        assert_eq!(h.filename, "harness.js");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_json_parse_harness_derives_entry_stem_from_entry_file() {
        let h = emit_json_parse_harness(&make_json_parse_spec("/abs/path/benign.js", "run"));
        assert!(h.source.contains("require('./benign')"));
    }

    fn make_unauthorized_id_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(EntryKind::Function, entry_name, PayloadSlot::Param(0));
        spec.expected_cap = Cap::UNAUTHORIZED_ID;
        spec.entry_file = entry_file.into();
        spec.entry_name = entry_name.into();
        spec
    }

    #[test]
    fn emit_dispatches_to_unauthorized_id_harness_when_cap_is_unauthorized_id() {
        let h = emit(
            &make_unauthorized_id_spec("tests/dynamic_fixtures/unauthorized_id/js/vuln.js", "run"),
            false,
        )
        .unwrap();
        assert!(
            h.source.contains("_nyx_idor_probe"),
            "dispatcher must short-circuit Cap::UNAUTHORIZED_ID into emit_unauthorized_id_harness: {}",
            h.source
        );
        assert!(
            h.source.contains("kind: 'IdorAccess'"),
            "UNAUTHORIZED_ID harness must emit ProbeKind::IdorAccess records: {}",
            h.source
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_pins_caller_id() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/js/vuln.js",
            "run",
        ));
        assert!(
            h.source.contains("const _NYX_CALLER_ID = 'alice';"),
            "harness must hard-code caller_id=alice so the predicate fires only when payload != alice: {}",
            h.source
        );
        assert!(
            h.source
                .contains("_nyx_idor_probe(_NYX_CALLER_ID, payload)"),
            "harness must emit the IDOR probe with the hard-coded caller and the payload owner_id: {}",
            h.source
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_skips_probe_when_record_is_nullish() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/js/benign.js",
            "run",
        ));
        assert!(
            h.source
                .contains("const materialised = record !== null && record !== undefined;"),
            "harness must guard the probe behind a null/undefined check so the benign fixture (which returns null on boundary cross) does not flip the predicate: {}",
            h.source
        );
        assert!(
            h.source.contains("if (materialised) {"),
            "harness must only emit the probe when the fixture materialised a record: {}",
            h.source
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_routes_through_fixture_require() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/js/vuln.js",
            "run",
        ));
        assert!(
            h.source.contains("function _nyx_idor_via_fixture(payload)"),
            "JS UNAUTHORIZED_ID harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(h.source.contains("require('./vuln')"));
        assert!(h.source.contains("_entry['run']"));
        assert_eq!(h.filename, "harness.js");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_unauthorized_id_harness_derives_entry_stem_from_entry_file() {
        let h =
            emit_unauthorized_id_harness(&make_unauthorized_id_spec("/abs/path/benign.js", "run"));
        assert!(h.source.contains("require('./benign')"));
    }

    fn make_data_exfil_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(EntryKind::Function, entry_name, PayloadSlot::Param(0));
        spec.expected_cap = Cap::DATA_EXFIL;
        spec.entry_file = entry_file.into();
        spec.entry_name = entry_name.into();
        spec
    }

    #[test]
    fn emit_dispatches_to_data_exfil_harness_when_cap_is_data_exfil() {
        let h = emit(
            &make_data_exfil_spec("tests/dynamic_fixtures/data_exfil/js/vuln.js", "run"),
            false,
        )
        .unwrap();
        assert!(
            h.source.contains("_NYX_http.request = _nyx_request_shim;"),
            "dispatcher must short-circuit Cap::DATA_EXFIL into emit_data_exfil_harness: {}",
            h.source
        );
        assert!(
            h.source.contains("kind: 'OutboundNetwork'"),
            "DATA_EXFIL harness must emit ProbeKind::OutboundNetwork records: {}",
            h.source
        );
    }

    #[test]
    fn emit_data_exfil_harness_shims_http_and_https_request() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/js/vuln.js",
            "run",
        ));
        assert!(h.source.contains("_NYX_http.request = _nyx_request_shim;"));
        assert!(h.source.contains("_NYX_http.get = _nyx_request_shim;"));
        assert!(h.source.contains("_NYX_https.request = _nyx_request_shim;"));
        assert!(h.source.contains("_NYX_https.get = _nyx_request_shim;"));
        assert!(
            h.source.contains("class _NyxFakeRequest"),
            "harness must return a fake request so the fixture does not block on real network egress: {}",
            h.source
        );
    }

    #[test]
    fn emit_data_exfil_harness_shims_global_fetch() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/js/vuln.js",
            "run",
        ));
        assert!(
            h.source
                .contains("global.fetch = async function _nyx_fetch_shim"),
            "harness must also intercept global.fetch so Node 18+ fixtures that use the WHATWG fetch API are captured: {}",
            h.source
        );
    }

    #[test]
    fn emit_data_exfil_harness_parses_host_from_options_and_url() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/js/vuln.js",
            "run",
        ));
        assert!(
            h.source.contains("target.hostname"),
            "harness must read hostname from options-object inputs: {}",
            h.source
        );
        assert!(
            h.source.contains("new URL(raw).hostname"),
            "harness must parse bare URL strings via WHATWG URL: {}",
            h.source
        );
    }

    #[test]
    fn emit_data_exfil_harness_routes_through_fixture_require() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/js/vuln.js",
            "run",
        ));
        assert!(
            h.source
                .contains("function _nyx_data_exfil_via_fixture(payload)"),
            "JS DATA_EXFIL harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(h.source.contains("require('./vuln')"));
        assert!(h.source.contains("_entry['run']"));
        assert_eq!(h.filename, "harness.js");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_data_exfil_harness_derives_entry_stem_from_entry_file() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec("/abs/path/benign.js", "run"));
        assert!(h.source.contains("require('./benign')"));
    }
}
