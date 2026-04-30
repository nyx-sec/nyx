use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &[
            "document.location",
            "window.location",
            "req.body",
            "req.query",
            "req.params",
            "req.headers",
            "req.cookies",
            "req.hostname",
            "req.ip",
            "req.path",
            "req.protocol",
            "req.url",
            "req.get",
            "req.header",
            "process.env",
            "location.search",
            "location.hash",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["JSON.parse"],
        label: DataLabel::Sanitizer(Cap::JSON_PARSE),
        case_sensitive: false,
    },
    // `encodeURIComponent` percent-encodes every character outside the
    // ASCII identifier alphabet, including `<`, `>`, `&`, `"`, `'`, so
    // the result is safe to embed in HTML text content and HTML
    // attribute values, not just URL components.  Treating it as
    // covering both URL_ENCODE and HTML_ESCAPE caps avoids FPs when a
    // wrapper that calls it is composed into an HTML sink (e.g.
    // `res.send('<p>' + cleanInput(x) + '</p>')`).  `encodeURI` keeps a
    // smaller reserved set (`?`, `&`, `=`, `+` are NOT encoded) so it
    // stays URL-only.
    LabelRule {
        matchers: &["encodeURIComponent"],
        label: DataLabel::Sanitizer(Cap::from_bits_truncate(
            Cap::URL_ENCODE.bits() | Cap::HTML_ESCAPE.bits(),
        )),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["encodeURI"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["DOMPurify.sanitize"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["xss"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["sanitizeHtml"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["validator.escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Type coercion sanitizers
    LabelRule {
        matchers: &["parseInt", "parseFloat", "Number"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["sanitizeUrl"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["shell-escape", "shellescape"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // he library, HTML entity encoding
    LabelRule {
        matchers: &["he.encode", "he.escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Conventional forwarding wrappers, telemetry / analytics / metrics dispatch.
    // Treating these as Sanitizer(DATA_EXFIL) encodes the project convention
    // that a payload routed through a named forwarding boundary is an
    // explicit, expected egress (the developer named the function), not the
    // accidental cross-boundary leak DATA_EXFIL is meant to catch.  Users who
    // do not follow this convention can override per-project via
    // [analysis.languages.javascript] custom rules; the convention is
    // documented in docs/detectors/taint.md so projects can extend it.
    LabelRule {
        matchers: &[
            "serializeForUpstream",
            "forwardPayload",
            "tracker.send",
            "analytics.track",
            "metrics.report",
            "logEvent",
        ],
        label: DataLabel::Sanitizer(Cap::DATA_EXFIL),
        case_sensitive: false,
    },
    // Conventional project-local HTML escapers.  Suffix word-boundary match
    // fires on bare calls to locally defined helpers (`function escapeHtml(x)`
    // invoked as `escapeHtml(x)`) across codebases that follow the common
    // naming convention.  Case-insensitive so `EscapeHtml` / `escapeHTML`
    // / `safeHTML` all qualify.
    LabelRule {
        matchers: &["escapeHtml", "escapeHTML", "htmlEscape", "safeHtml"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["eval"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["innerHTML", "dangerouslySetInnerHTML"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "location.href",
            "window.location.href",
            "document.location.href",
        ],
        label: DataLabel::Sink(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // Shell-exec sinks. Qualified `child_process.*` and bare destructured-
    // import forms (`exec`, `execSync`, `execFile`, ...) are both modeled as
    // flat sinks here so module-aliased call sites like `cp.exec(...)`
    // (where `cp = require('child_process')`) still fire via suffix match.
    // The bare-form FPs that motivated tightening are addressed elsewhere:
    //
    //   * `container.exec(...)` (Dockerode) and `exec.start(...)` (the
    //     resulting `exec` handle) — `container.exec` is excluded via the
    //     EXCLUDES list below; `exec.start` is suppressed by restricting
    //     `first_member_label`'s suffix-strip-and-retry to `Source` labels
    //     only (see `cfg/helpers.rs`).
    //   * `execSync(cmd, { env: process.env })` flagging `process.env`
    //     flowing into the options arg — addressed by the
    //     `=exec`/`=execSync`/`=execFile`/... gates in `GATED_SINKS` below
    //     which set `payload_args: &[0]`.  The cfg pass propagates a gate's
    //     payload_args restriction onto the matching flat sink so only arg
    //     0 (the command string) is taint-checked at the call site.
    LabelRule {
        matchers: &[
            "child_process.exec",
            "child_process.execSync",
            "child_process.spawn",
            "child_process.execFile",
            // Bare forms from destructured imports:
            //   const { exec, execSync } = require('child_process')
            // and module-aliased calls like `cp.exec(...)`.  Receiver-name
            // collisions (`container.exec`, etc.) are suppressed via
            // EXCLUDES; arg-position restriction comes from the `=*` gates.
            "exec",
            "execSync",
            "execFile",
            // Common promisified wrappers around child_process.exec
            "execAsync",
            "execPromise",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
    },
    // ── Outbound HTTP clients, modeled as destination-aware gated sinks ──
    // Flat-Sink modeling of fetch/axios/got/undici/http.request was producing
    // a dominant FP class where any tainted body/payload arg appeared as SSRF
    // (e.g. `fetch("/api/telemetry", { body: navigator.userAgent })`). SSRF
    // semantics require attacker control over the *destination*, not the
    // payload.  The gated entries in `GATED_SINKS` below narrow SSRF
    // activation to URL / host / path / origin arguments or object fields.
    // Taint flowing only to body / data / json / headers is captured by a
    // *separate* gate class (`Cap::DATA_EXFIL`) so the two can coexist on
    // the same callee without one over-flagging the other.
    // Express response sinks
    LabelRule {
        matchers: &["res.send", "res.json"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["res.redirect"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["res.sendFile", "res.download"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["res.set", "res.header"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // DOM XSS sinks
    LabelRule {
        matchers: &[
            "document.write",
            "document.writeln",
            "outerHTML",
            "insertAdjacentHTML",
        ],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Navigation / open-redirect sinks
    LabelRule {
        matchers: &["location.assign", "location.replace", "window.open"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Node.js file-system sinks
    LabelRule {
        matchers: &[
            "fs.writeFile",
            "fs.writeFileSync",
            "fs.readFile",
            "fs.readFileSync",
            "fs.createReadStream",
            "fs.createWriteStream",
            "fs.access",
            "fs.stat",
            "fs.statSync",
            "fs.unlink",
            "fs.unlinkSync",
            "fs.readdir",
            "fs.readdirSync",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    // Node.js network sinks
    LabelRule {
        matchers: &["net.createConnection"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // ── Cross-boundary data exfiltration (DATA_EXFIL) ─────────────────────
    //
    // `XMLHttpRequest.prototype.send(body)`, when the receiver type is
    // tracked back to `new XMLHttpRequest()`, the SSA engine's type-qualified
    // resolver converts `xhr.send` to `HttpClient.send`; matching that form
    // fires DATA_EXFIL on tainted body flow.  The explicit
    // `XMLHttpRequest.prototype.send.apply(...)` form is also covered.  The
    // `fetch` body / headers / json case is covered by the gated entry in
    // `GATED_SINKS` (so SSRF on the URL and DATA_EXFIL on the payload can
    // coexist on a single call site).
    LabelRule {
        matchers: &["HttpClient.send", "XMLHttpRequest.prototype.send"],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
    },
    // ─────────── SQL injection sinks ─────────────
    // Database drivers: mysql, mysql2, pg, better-sqlite3
    LabelRule {
        matchers: &[
            "connection.query",
            "client.query",
            "pool.query",
            "db.query",
            "db.execute",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // ORM / query builder raw-SQL entry points.
    //
    // `$queryRaw` / `$executeRaw` are tagged-template forms; the SQL is
    // assembled from a template literal so taint reaching arg 0 is the
    // injection vector and modeling them as flat sinks is correct.
    //
    // `$queryRawUnsafe` / `$executeRawUnsafe` accept positional bind
    // parameters: `tx.$queryRawUnsafe(sqlTemplate, p1, p2, ...)` binds
    // p1..pN as `$1..$N` (PostgreSQL prepared-statement params) and the SQL
    // template at arg 0 is the only injection point.  These are modeled as
    // gated sinks below (`payload_args: &[0]`) so taint flowing only into
    // the bind params no longer fires.  `sequelize.query` and `knex.raw`
    // also accept a separate bind-params object/array but the bind-params
    // interface is non-positional in those APIs, so they stay flat for now.
    LabelRule {
        matchers: &["sequelize.query", "knex.raw", "$queryRaw", "$executeRaw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
];

/// Callee patterns that must never be classified as source/sanitizer/sink.
/// Express/Koa route-registration methods look like `router.get(path, handler)`
/// and could collide with source matchers like `req.get`.
/// Also excludes non-user-controlled `req.*` properties (session, app, route).
pub static EXCLUDES: &[&str] = &[
    // Express route registration
    "router.get",
    "router.post",
    "router.put",
    "router.delete",
    "router.patch",
    "router.use",
    "router.all",
    "app.get",
    "app.post",
    "app.put",
    "app.delete",
    "app.patch",
    "app.use",
    "app.all",
    // Non-user-controlled req properties
    "req.session",
    "req.app",
    "req.route",
    "req.next",
    // Session management lifecycle methods
    "req.session.destroy",
    "req.session.regenerate",
    "req.session.save",
    "req.session.reload",
    // Dockerode container API: `container.exec({ Cmd: [...] })` is the
    // canonical non-shell exec path (the Cmd array is passed directly to
    // the kernel via `execve`, no shell parsing).  `exec.start(...)` is
    // the follow-on stream attach.  Suffix-matching the bare `exec` rule
    // would otherwise classify every `<receiver>.exec(...)` method call
    // — including these — as a SHELL_ESCAPE sink.  These patterns name
    // the Dockerode SDK methods specifically; if a project happens to
    // also expose its own `container.exec` shell wrapper, override via
    // [analysis.languages.javascript] custom rules.
    "container.exec",
    "exec.start",
];

pub static GATED_SINKS: &[SinkGate] = &[
    SinkGate {
        callee_matcher: "setAttribute",
        arg_index: 0,
        dangerous_values: &["href", "src", "action", "formaction", "srcdoc"],
        dangerous_prefixes: &["on"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    SinkGate {
        callee_matcher: "parseFromString",
        arg_index: 1,
        dangerous_values: &["text/html", "application/xhtml+xml"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // ── Outbound HTTP clients (SSRF) ──────────────────────────────────────
    //
    // Policy: SSRF fires only when taint reaches the destination-bearing
    // argument or object field (URL / host / path / origin). Taint flowing
    // only to body / data / json / headers / payload is silenced. See the
    // commentary at the top of RULES for the rationale.
    //
    // `fetch(input, init)`, arg 0 can be a URL string OR a Request/config
    // object with `url`. Per WHATWG Fetch, when `input` is a dictionary, the
    // URL field is canonically `url`. Init-object body/headers at arg 1 are
    // *not* destination-bearing.
    SinkGate {
        callee_matcher: "fetch",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["url"],
        },
    },
    // `axios(config)` / `axios.request(config)`, config object exposes
    // `url` and `baseURL`. Body-ish fields (`data`, `params`, `headers`)
    // are excluded.
    SinkGate {
        callee_matcher: "axios",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["url", "baseURL"],
        },
    },
    SinkGate {
        callee_matcher: "axios.request",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["url", "baseURL"],
        },
    },
    // `axios.get(url[, config])`, arg 0 is URL; arg 1 is config.
    SinkGate {
        callee_matcher: "axios.get",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `axios.post(url, data[, config])`, arg 0 is URL; `data` at arg 1 is
    // the request body and must NOT activate SSRF.
    SinkGate {
        callee_matcher: "axios.post",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `axios.put / axios.patch / axios.delete` follow the same shape ,
    // (url, data?, config?). Keep the model consistent across verbs.
    SinkGate {
        callee_matcher: "axios.put",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "axios.patch",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "axios.delete",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `got(url[, options])` / `got(options)`, options exposes `url` and
    // `prefixUrl`. Body-ish fields (`body`, `json`, `form`, `searchParams`,
    // `headers`) are excluded.
    SinkGate {
        callee_matcher: "got",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["url", "prefixUrl"],
        },
    },
    // `undici.request(url | opts[, opts])`, opts exposes `origin` and
    // `path`. Body-ish fields (`body`, `headers`) are excluded.
    SinkGate {
        callee_matcher: "undici.request",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["origin", "path"],
        },
    },
    // Node `http.request(options[, cb])` / `https.request(options[, cb])` ,
    // options exposes `host`, `hostname`, `path`, `protocol`, `port`,
    // `origin`. Body is sent via `.write()`/`.end()` on the returned
    // ClientRequest, so it never appears as a positional arg here.
    // Arg 0 may also be a URL string, the "whole arg is destination"
    // fallback (triggered when arg 0 is not an object literal) covers that.
    SinkGate {
        callee_matcher: "http.request",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["host", "hostname", "path", "protocol", "port", "origin"],
        },
    },
    SinkGate {
        callee_matcher: "https.request",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["host", "hostname", "path", "protocol", "port", "origin"],
        },
    },
    // Node `http.get(options[, cb])` / `https.get(options[, cb])` ,
    // convenience wrappers around `.request()` that auto-call `.end()`.
    // Same destination semantics as `.request`. Motivated by
    // CVE-2025-64430 (Parse Server SSRF via http.get(uri)).
    SinkGate {
        callee_matcher: "http.get",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["host", "hostname", "path", "protocol", "port", "origin"],
        },
    },
    SinkGate {
        callee_matcher: "https.get",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["host", "hostname", "path", "protocol", "port", "origin"],
        },
    },
    // ── Cross-boundary data exfiltration ──────────────────────────────────
    //
    // Sensitive data flowing into the *payload* of an outbound request is a
    // distinct vulnerability class from SSRF: the destination is fixed but
    // attacker-influenced bytes leave the process via the request body /
    // headers / json field.  These gates fire on the body-bearing positions
    // and emit `Cap::DATA_EXFIL`, which is intentionally separate from
    // `Cap::SSRF` so a `fetch(taintedUrl, {body: tainted})` site reports
    // both classes independently.
    //
    // `fetch(input, init)`, `init` at arg 1 carries body / headers / json.
    SinkGate {
        callee_matcher: "fetch",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["body", "headers", "json"],
        },
    },
    // ── Shell-exec sinks (SHELL_ESCAPE) ──────────────────────────────────
    //
    // Only arg 0 (the command string) is a shell-injection payload.
    // `options.env` / `options.cwd` / etc. at arg 1+ are not.  Bare forms
    // (`exec`, `execSync`, `execFile`, `execAsync`, `execPromise`) use the
    // `=` exact-only sigil so they match the destructured-import shape
    // (`const { exec } = require('child_process'); exec(cmd)`) without
    // colliding with any `<receiver>.exec` method (Dockerode's
    // `container.exec`, `RegExp.prototype.exec`, etc.).
    // Qualified `child_process.*` forms stay as flat sinks (see RULES above);
    // gates run only when no flat sink already classifies the call, so adding
    // them here would never fire.  The bare destructured-import forms below
    // are the only place where shell-exec needs gating, since `classify_all`
    // can't safely register a bare `exec` rule without colliding with every
    // `<receiver>.exec` method (Dockerode `container.exec`,
    // `RegExp.prototype.exec`, etc.).
    SinkGate {
        callee_matcher: "=exec",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "=execSync",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "=execFile",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "=execAsync",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "=execPromise",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // ── Prisma raw-SQL with positional bind params (SQL_QUERY) ───────────
    //
    // `tx.$queryRawUnsafe(sqlTemplate, p1, p2, ...)` binds `p1..pN` as
    // PostgreSQL `$1..$N` prepared-statement parameters; only arg 0 (the
    // SQL template) is the injection vector.  Flat sinks here flagged taint
    // flowing only into bind params, which is equivalent to a parameterised
    // query and not exploitable.  Suffix-match (no `=` sigil) so
    // `tx.$queryRawUnsafe`, `prisma.$queryRawUnsafe`, etc. all qualify.
    SinkGate {
        callee_matcher: "$queryRawUnsafe",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "$executeRawUnsafe",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,
    "for_in_statement"      => Kind::For,
    "do_statement"          => Kind::While,

    "return_statement"      => Kind::Return,
    "throw_statement"       => Kind::Throw,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "program"               => Kind::SourceFile,
    "statement_block"       => Kind::Block,
    "else_clause"           => Kind::Block,
    "function_declaration"  => Kind::Function,
    "function_expression"   => Kind::Function,
    "arrow_function"        => Kind::Function,
    "method_definition"     => Kind::Function,
    "generator_function_declaration" => Kind::Function,
    "generator_function"    => Kind::Function,
    "switch_statement"      => Kind::Switch,
    "switch_body"           => Kind::Block,
    "switch_case"           => Kind::Block,
    "switch_default"        => Kind::Block,
    "try_statement"         => Kind::Try,
    "catch_clause"          => Kind::Block,
    "finally_clause"        => Kind::Block,
    "class_declaration"     => Kind::Block,
    "class"                 => Kind::Block,
    "class_body"            => Kind::Block,
    "export_statement"      => Kind::Block,

    // data-flow
    "call_expression"       => Kind::CallFn,
    "new_expression"        => Kind::CallFn,
    "assignment_expression" => Kind::Assignment,
    "variable_declaration"  => Kind::CallWrapper,
    "lexical_declaration"   => Kind::CallWrapper,
    "expression_statement"  => Kind::CallWrapper,

    // trivia
    "comment"               => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_statement"      => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["identifier"],
    self_param_kinds: &[],
    ident_fields: &["name", "pattern"],
};

/// Framework-conditional rules for JavaScript.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Koa) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "ctx.request.body".into(),
                "ctx.request.query".into(),
                "ctx.request.querystring".into(),
                "ctx.request.params".into(),
                "ctx.request.headers".into(),
                "ctx.request.header".into(),
                "ctx.request.get".into(),
                "ctx.query".into(),
                "ctx.params".into(),
                "ctx.headers".into(),
                "ctx.header".into(),
                "ctx.get".into(),
                "ctx.cookies.get".into(),
                "ctx.hostname".into(),
                "ctx.ip".into(),
                "ctx.path".into(),
                "ctx.protocol".into(),
                "ctx.url".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["ctx.body".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["ctx.redirect".into()],
            label: DataLabel::Sink(Cap::SSRF),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["ctx.set".into(), "ctx.append".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    if ctx.has(DetectedFramework::Fastify) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "request.body".into(),
                "request.query".into(),
                "request.params".into(),
                "request.headers".into(),
                "request.cookies".into(),
                "request.hostname".into(),
                "request.ip".into(),
                "request.url".into(),
                "request.raw.headers".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["reply.send".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["reply.redirect".into()],
            label: DataLabel::Sink(Cap::SSRF),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["reply.sendFile".into(), "reply.download".into()],
            label: DataLabel::Sink(Cap::FILE_IO),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["reply.header".into(), "reply.headers".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    rules
}
