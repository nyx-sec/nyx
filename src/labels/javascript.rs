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
    // (Lodash `_.template` is modeled as a gated sink in `GATED_SINKS`
    //  below — the gate inspects arg 1's options object so the patched
    //  `{ evaluate: false }` form is suppressed.)
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
    // ─── LDAP injection sinks ───
    //
    // `ldapjs`: both the bound-variable idiom
    // `const client = ldap.createClient({...}); client.search(...)` and the
    // chained idiom `ldap.createClient({...}).search(...)` are covered by
    // type-qualified receiver resolution.  The receiver of the inner call is
    // typed `TypeKind::LdapClient` via `ssa::type_facts::constructor_type`,
    // and (for the bound-variable form) closure-captured types are forwarded
    // into the per-function type-fact result by
    // [`crate::taint::inject_external_type_facts`], so the qualified callee
    // text resolves to `LdapClient.search` in both shapes.
    LabelRule {
        matchers: &["LdapClient.search"],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── LDAP-filter sanitizers ───
    //
    // The `ldap-escape` package exports `filter` and `dn` tagged-template
    // helpers (`filter`\`(uid=${input})\``).  After tree-sitter lifts the
    // template-tag identifier, the callee text is the function name; suffix
    // matching on `ldapEscape` / `ldapescape` covers `const ldapEscape =
    // require('ldap-escape')` plus default-import shapes.
    LabelRule {
        matchers: &["ldapEscape", "ldap-escape", "ldapescape.filter", "ldapescape.dn"],
        label: DataLabel::Sanitizer(Cap::LDAP_INJECTION),
        case_sensitive: false,
    },
    // ─── XPath injection sinks ───
    //
    // `document.evaluate(expr, contextNode, ...)` (DOM) and the npm `xpath`
    // package's `xpath.select(expr, doc)` / `xpath.evaluate(expr, doc, ...)`
    // accept the expression string as arg 0; concatenated user input there
    // is the canonical XPath-injection vector.
    LabelRule {
        matchers: &[
            "document.evaluate",
            "xpath.select",
            "xpath.evaluate",
            "xpath.select1",
        ],
        label: DataLabel::Sink(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // ─── XPath escape sanitizers ───
    //
    // No standard library helper escapes XPath metacharacters; project-local
    // `escapeXpath` / `xpathEscape` are the developer-named equivalents.
    LabelRule {
        matchers: &["escapeXpath", "xpathEscape", "escape_xpath"],
        label: DataLabel::Sanitizer(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF injection sinks ───
    //
    // Express/Fastify/Node `http` response APIs that write a single header
    // value: `res.setHeader(name, val)` (case-insensitive verb), `res.set`,
    // `res.header`, `res.append`.  Tainted strings here without `\r\n`
    // stripping let an attacker inject extra headers (response splitting).
    LabelRule {
        matchers: &["setHeader", "res.set", "res.header", "res.append"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // Subscript-set form: `res.headers["X-Foo"] = bar` /
    // `response.headers["X-Foo"] = bar`.  The LHS-subscript classification
    // path in `cfg/mod.rs::push_node` walks into the subscript's `object`
    // and classifies its member-expression text, so the bare bracket form
    // fires alongside `setHeader` / `res.set` / `res.header` / `res.append`.
    LabelRule {
        matchers: &[
            "res.headers",
            "response.headers",
            "self.response.headers",
        ],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF sanitizers ───
    //
    // Project-local `stripCRLF` / `escapeHeader` helpers that strip `\r` and
    // `\n` from a value before it is written to a response header.
    LabelRule {
        matchers: &["stripCRLF", "stripCrlf", "escapeHeader", "sanitizeHeader"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Prototype pollution sinks (library-mediated) ───
    //
    // Recursive merge / deep-assign helpers from lodash / common bundles.
    // Argument-role gating (target vs src) is enforced via Destination
    // activation in `GATED_SINKS` below: only taint flowing into the
    // source-object arguments (positions 1+) activates; tainted-target-
    // only is benign because writes to a tainted target object don't
    // pollute `Object.prototype`.  Flat rules here are intentionally
    // empty for the merge family; see GATED_SINKS for the per-call
    // gating.  `_.template` is excluded — it is handled separately as
    // a gated CODE_EXEC sink (Strapi CVE-2023-22621 evaluate:false
    // suppression).
    // ─── Open redirect sinks ───
    //
    // Express response redirect: `res.redirect(url)`.  Browser-side
    // navigation: `location.replace` / `location.assign` fire as direct
    // calls; `window.location = url` / `window.location.href = url` /
    // `location.href = url` fire as assignment-LHS sinks via the
    // `member_expr_text` classification path in `cfg::push_node`.
    // `router.navigate` covers the Angular Router (`Router.navigate`,
    // `Router.navigateByUrl`) and the React-Router `useNavigate`-returned
    // `navigate` function; suffix matching catches both the bound-receiver
    // and direct-call shapes.
    LabelRule {
        matchers: &[
            "res.redirect",
            "location.replace",
            "location.assign",
            "router.navigate",
            "router.navigateByUrl",
            "window.location",
            "window.location.href",
            "location.href",
        ],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    // ─── Open-redirect URL allowlist sanitizers ───
    //
    // Project-local helpers that allowlist hosts or enforce relative-only
    // URLs.  `validateRedirectUrl` / `isSafeRedirect` are the canonical
    // developer-named allowlist helpers; `stripScheme` clears any absolute
    // scheme and degrades the URL to a relative path.  `ensureRelativeUrl`
    // / `assertRelativePath` cover the leading-slash / no-scheme idiom.
    LabelRule {
        matchers: &[
            "validateRedirectUrl",
            "isSafeRedirect",
            "stripScheme",
            "ensureRelativeUrl",
            "assertRelativePath",
            "isRelativeUrl",
        ],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    // ─── SSTI sinks ───
    //
    // Template-engine entry points that accept the template *source string*
    // as the first argument: tainted arg 0 lets the attacker drive
    // arbitrary template execution.  `_.template` is excluded — it has
    // its own gated CODE_EXEC classifier (Strapi CVE-2023-22621) that
    // respects the `evaluate:false` opt-out.  `nunjucks.renderString` is
    // also excluded — see GATED_SINKS below for arg-0-only payload
    // gating (suppresses tainted-`ctx`-only flows).
    LabelRule {
        matchers: &["Handlebars.compile"],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: false,
    },
    // ─── XXE sinks ───
    //
    // libxmljs `parseXmlString` / `parseXml` resolve external entities by
    // default when called with `{ noent: true }` or
    // `{ replaceEntities: true }`.  The flat-rule modeling treats any call
    // as a sink, the safe path requires explicit option suppression.
    // libxmljs's own default ignores entities so the sink is conservative
    // here; xml2js / fast-xml-parser are gated below in GATED_SINKS to
    // suppress the safe-default case.
    LabelRule {
        matchers: &["libxmljs.parseXmlString", "libxmljs.parseXml"],
        label: DataLabel::Sink(Cap::XXE),
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
    // Lodash `_.template(template, options?)` — server-side template
    // injection sink.  Lodash's template parser by default compiles
    // `<% ... %>` evaluate blocks into a JavaScript Function via the
    // `Function` constructor; when the template string is attacker-
    // controlled this is RCE (Strapi CVE-2023-22621 et al.).
    //
    // Gate: activate on arg 0 (the template string).  Inspect arg 1's
    // options object for `evaluate: false`; when present as a literal
    // the evaluate-block compiler is disabled and the call is safe.
    // Missing arg 1, missing `evaluate` key, or a dynamic value all
    // fall through `ValueMatch`'s `None` branch and fire conservatively.
    //
    // The `keyword_name`-based activation reads the property value via
    // the JS-side closure augmentation in `cfg/mod.rs`, which falls
    // back to walking the call's arg-1 object literal when the
    // language-default `keyword_argument` extraction yields nothing.
    SinkGate {
        callee_matcher: "_.template",
        arg_index: 0,
        dangerous_values: &["true"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: Some("evaluate"),
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    SinkGate {
        callee_matcher: "lodash.template",
        arg_index: 0,
        dangerous_values: &["true"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: Some("evaluate"),
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // ── XML XXE gates ─────────────────────────────────────────────────────
    //
    // `xml2js.parseString(xml, opts, cb)` is XXE-safe by default; opts
    // `{ explicitChildren: true, charkey: '__cdata' }` are benign, but
    // resolving entities at the underlying sax-js layer requires user
    // intent.  The gate fires only when the option object literal carries
    // an entity-resolution kwarg with a truthy value (or is dynamic).  Only
    // the XML payload (arg 0) is the protected position.
    SinkGate {
        callee_matcher: "xml2js.parseString",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[
            ("processEntities", &["true"]),
            ("explicitEntities", &["true"]),
            ("strict", &["false"]),
        ],
        activation: GateActivation::ValueMatch,
    },
    // Note: `fast-xml-parser` (`new XMLParser({...}).parse(xml)`) is XXE-safe
    // by default; flagging it would require constructor-option tracking via
    // TypeFacts (XmlParser type with config carry).  Deferred to Layer 2.
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
    // `nunjucks.renderString(src, ctx)` — Nunjucks SSTI sink.  Only the
    // template *source* (arg 0) lets an attacker drive template execution;
    // the `ctx` data object (arg 1) is rendered via the template's escape
    // policy and is not itself a code-injection vector.  Gate via
    // Destination-style activation with `payload_args: &[0]` so taint
    // flowing only into `ctx` is suppressed.
    SinkGate {
        callee_matcher: "nunjucks.renderString",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // ── Prototype pollution gates ────────────────────────────────────────
    //
    // Library-mediated recursive merge / deep-assign helpers.  Argument-
    // role gating: `(target, src1, src2, ...)` — only taint reaching a
    // *source* position (index 1+) can pollute `Object.prototype` via
    // `__proto__` / `constructor` keys on attacker-controlled input.
    // Tainted target alone is benign (it just mutates that object).
    // `payload_args: &[1, 2, 3, 4, 5]` covers the canonical 1-target +
    // up-to-5-source signatures used by lodash / Object.assign / jQuery
    // extend; arity beyond 5 is rare in practice and would over-suppress
    // only at the long tail.
    SinkGate {
        callee_matcher: "_.merge",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: false,
        payload_args: &[1, 2, 3, 4, 5],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "_.mergeWith",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: false,
        payload_args: &[1, 2, 3, 4, 5],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "_.defaultsDeep",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: false,
        payload_args: &[1, 2, 3, 4, 5],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `_.set(obj, path, value)` — both `path` (arg 1) and `value` (arg 2)
    // can drive prototype pollution: a tainted path of `__proto__.foo`
    // mutates `Object.prototype`, and a tainted value into `obj.__proto__`
    // does the same.  Object (arg 0) is the canonical target.
    SinkGate {
        callee_matcher: "_.set",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: false,
        payload_args: &[1, 2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "_.setWith",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: false,
        payload_args: &[1, 2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // Generic project-local deep-merge helpers.  Suffix-matched so any
    // `*.deepMerge` / `*.defaultsDeep` qualified call also resolves.
    SinkGate {
        callee_matcher: "deepMerge",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: false,
        payload_args: &[1, 2, 3, 4, 5],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "defaultsDeep",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: false,
        payload_args: &[1, 2, 3, 4, 5],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `Object.assign(target, ...sources)` is safe with constant-literal
    // sources (`{a: 1, b: 2}`) but dangerous with attacker-controlled
    // input (`req.body`).  Gate target out of payload_args so tainted-
    // target alone does not fire.
    SinkGate {
        callee_matcher: "Object.assign",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: true,
        payload_args: &[1, 2, 3, 4, 5],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // jQuery / Zepto `$.extend(target, ...sources)` and `jQuery.extend`.
    // Arg 0 may be a deep-flag boolean (`true`) when the deep-merge form
    // is in use, in which case sources start at arg 2.  Cover both
    // shapes by listing arg 1, 2, 3, 4 in `payload_args`: a `true` first
    // arg never carries taint, so its inclusion is harmless; for the
    // shallow `$.extend(target, src)` form, src at arg 1 still fires.
    SinkGate {
        callee_matcher: "$.extend",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: true,
        payload_args: &[1, 2, 3, 4],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "jQuery.extend",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: true,
        payload_args: &[1, 2, 3, 4],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `set-value` standalone helper: `setValue(obj, key, val)` — historic
    // CVE-2019-10747 (set-value <2.0.1) and CVE-2021-23440 (set-value <4.0.1)
    // recursive set-by-path helper that did not block `__proto__` keys.
    // Suffix-matched so qualified imports (`require('set-value')`) bound to
    // `setValue` still resolve.
    SinkGate {
        callee_matcher: "setValue",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: true,
        payload_args: &[1, 2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `dot-prop` standalone helper: `dotProp.set(obj, path, val)` —
    // CVE-2020-8116.  Path is a dotted-string with prototype-key support;
    // a tainted `path` of `__proto__.x` mutates Object.prototype.
    SinkGate {
        callee_matcher: "dotProp.set",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: true,
        payload_args: &[1, 2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `JSONPath` / `jsonpath-plus` `JSONPath({path: p, json: o, callback: fn})`
    // historically supported a `resultType: 'value'` mode that, combined with
    // `parent`/`parentProperty` writes inside the callback, can mutate the
    // prototype chain.  Recognise the `jp.set(obj, path, value)` family
    // (jsonpath, jsonpath-plus) on the same shape as `_.set`.
    SinkGate {
        callee_matcher: "jp.set",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: true,
        payload_args: &[1, 2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "jsonpath.set",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: false,
        payload_args: &[1, 2],
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
    // `identifier` covers bare params (`a`); `assignment_pattern` covers
    // default-value params (`a = {}`). Without `assignment_pattern`,
    // tree-sitter wraps the identifier in a node the param walker
    // doesn't recognize, and `extract_param_meta` produces a
    // parameter-less summary for any function whose params have
    // defaults — breaking cross-function `param_to_sink` propagation
    // for shapes like `(emailOptions = {}, emailTemplate = {}, data = {}) => …`.
    // `object_pattern` covers destructured object formals (`({ a, b })`),
    // which tree-sitter-javascript exposes as a direct child of
    // `formal_parameters` (no `required_parameter` wrapper as in TS).
    // Without it the per-parameter probe never seeds the destructured
    // bindings and summary extraction misses `validated_params_to_return`
    // for shapes like `({ value }) => { validate(value); ... }` —
    // residual gap behind CVE-2026-25544.
    param_node_kinds: &["identifier", "assignment_pattern", "object_pattern"],
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
