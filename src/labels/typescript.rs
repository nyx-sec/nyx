use crate::labels::{
    Cap, DataLabel, GateActivation, GatedLabelRule, Kind, LabelGate, LabelRule, ParamConfig,
    RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    // The page's own origin components (`window.location.origin`, `.host`,
    // ...) name the site being served, not request text the visitor
    // chose, so a redirect built from them stays same-origin.  They remain
    // sources for every other cap (DOM XSS, SSRF).  `pathname`, `search`,
    // `hash` and `href` stay full sources: `//evil.com` and `?next=` reach
    // the redirect through them.  This rule precedes the `window.location`
    // source below so the longer spelling wins.
    LabelRule {
        matchers: &[
            "window.location.origin",
            "window.location.host",
            "window.location.hostname",
            "window.location.protocol",
            "window.location.port",
            "document.location.origin",
            "document.location.host",
            "document.location.hostname",
            "document.location.protocol",
            "document.location.port",
        ],
        label: DataLabel::Source(Cap::all().difference(Cap::OPEN_REDIRECT)),
        case_sensitive: false,
    },
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
    // Phase 10 — Web `Request` receiver-method reads.  Triggered when
    // the SSA receiver carries `TypeKind::Request` (Next.js App
    // Router handler's first formal) and the type-qualified resolver
    // rewrites `req.json()` → `Request.json` etc.  The reads return
    // user-controlled bytes / strings; the matchers also cover
    // `Request.url` and `Request.headers.get(...)` which both expose
    // header / URL state to the handler.
    LabelRule {
        matchers: &[
            "Request.json",
            "Request.formData",
            "Request.text",
            "Request.url",
            "Request.headers.get",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: true,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["JSON.parse"],
        label: DataLabel::Sanitizer(Cap::JSON_PARSE),
        case_sensitive: false,
    },
    // See javascript.rs for rationale: encodeURIComponent is safe for
    // HTML text and attribute contexts because it percent-encodes <, >,
    // &, ", '.
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
    // `path.basename` keeps only the final component, so a request value
    // reduced to it cannot climb out of the directory it is joined under.
    // `path.posix.basename` splits on `/` alone, so on a Windows host a
    // `..\` component survives it; it is not listed.
    LabelRule {
        matchers: &["path.basename", "path.win32.basename"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // he library, HTML entity encoding
    LabelRule {
        matchers: &["he.encode", "he.escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Conventional forwarding wrappers, telemetry / analytics / metrics dispatch.
    // See javascript.rs for rationale; mirrored here so TypeScript projects pick
    // up the same convention.  Override per-project via
    // [analysis.languages.typescript] custom rules.
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
    // Dynamic code construction (`new Function(src)`, `Function(src)`) and
    // the `vm` compile entry points.  See javascript.rs for the rationale.
    LabelRule {
        matchers: &[
            "=Function",
            "vm.runInNewContext",
            "vm.runInThisContext",
            "vm.runInContext",
            "vm.compileFunction",
            "vm.Script",
        ],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: true,
    },
    // Shell-exec sinks.  Only module-qualified `child_process.*` forms are
    // flat; aliased (`cp.exec`) and destructured (`spawn`) forms ride the
    // import-gated rule in `GATED_LABEL_RULES`, so `RegExp.prototype.exec`,
    // mongoose `Query.exec()` and sqlite `db.exec(sql)` never match.  The
    // `GATED_SINKS` entries restrict the checked args to arg 0.  See
    // javascript.rs for the full rationale.
    LabelRule {
        matchers: &[
            "child_process.exec",
            "child_process.execSync",
            "child_process.execFile",
            "child_process.execFileSync",
            "child_process.spawn",
            "child_process.spawnSync",
            "child_process.fork",
            "execAsync",
            "execPromise",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
    },
    // ── Outbound HTTP clients, modeled as destination-aware gated sinks ──
    // See GATED_SINKS below; rationale mirrors javascript.rs.
    LabelRule {
        matchers: &[
            "location.href",
            "window.location.href",
            "document.location.href",
        ],
        label: DataLabel::Sink(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // Express response sinks.  The matching `GATED_SINKS` entries keep the
    // `res` receiver out of the payload; see javascript.rs.
    // JSON responses (`res.json`, a Koa `ctx.body` object or array literal) are
    // not modelled as direct XSS sinks: they are sent with
    // `Content-Type: application/json`, which browsers do not render as HTML.
    LabelRule {
        matchers: &["res.send"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // `res.redirect` is OPEN_REDIRECT only (dedicated rule below): a 302 to the
    // browser is client-side navigation, not SSRF.
    LabelRule {
        matchers: &["res.sendFile", "res.download"],
        label: DataLabel::Sink(Cap::FILE_IO),
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
            "fs.accessSync",
            "fs.open",
            "fs.openSync",
            "fs.mkdir",
            "fs.mkdirSync",
            "fs.rm",
            "fs.rmSync",
            "fs.rmdir",
            "fs.rmdirSync",
            "fs.rename",
            "fs.renameSync",
            "fs.copyFile",
            "fs.copyFileSync",
            // Arg 1 is the appended data; `GATED_SINKS` restricts to arg 0.
            "fs.appendFile",
            "fs.appendFileSync",
            // Phase 05 — `node:fs/promises` member-access forms covered
            // here. Bare-name forms (`readFile`, `open`, ...) and
            // `fsp.readFile` namespace-import forms ride the gated
            // matcher in `GATED_LABEL_RULES`. Receiver-type fallback
            // synthesises `FileSystemPromisesNs.<method>` (handled
            // below).
            "fs.promises.readFile",
            "fs.promises.writeFile",
            "fs.promises.unlink",
            "fs.promises.open",
            "fs.promises.stat",
            "fs.promises.readdir",
            "fs.promises.mkdir",
            "fs.promises.rmdir",
            "fs.promises.rm",
            "fs.promises.appendFile",
            "fs.promises.copyFile",
            "fs.promises.rename",
            "fs.promises.truncate",
            "fs.promises.chmod",
            "FileSystemPromisesNs.readFile",
            "FileSystemPromisesNs.writeFile",
            "FileSystemPromisesNs.unlink",
            "FileSystemPromisesNs.open",
            "FileSystemPromisesNs.stat",
            "FileSystemPromisesNs.readdir",
            "FileSystemPromisesNs.mkdir",
            "FileSystemPromisesNs.rmdir",
            "FileSystemPromisesNs.rm",
            "FileSystemPromisesNs.appendFile",
            "FileSystemPromisesNs.copyFile",
            "FileSystemPromisesNs.rename",
            "FileSystemPromisesNs.truncate",
            "FileSystemPromisesNs.chmod",
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
    // See javascript.rs for rationale.  `xhr.send(body)` resolves to
    // `HttpClient.send` via type-qualified resolution.
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
            // better-sqlite3 / sqlite3 `db.exec(sql)` runs a raw SQL string.
            // (A bare `exec` suffix used to classify it as a shell sink.)
            "db.exec",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // ORM / query builder raw-SQL entry points.  `$queryRawUnsafe` /
    // `$executeRawUnsafe` are gated below — only arg 0 (the SQL template) is
    // the injection vector; positional bind params are bound as `$1..$N`.
    // See javascript.rs for the full rationale.
    LabelRule {
        matchers: &["sequelize.query", "knex.raw", "$queryRaw", "$executeRaw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // ── Phase 07 — ORM query-builder receiver-typed sinks ──
    // See `labels/javascript.rs` for the design rationale; mirrored here so
    // TypeScript fixtures pick up the same coverage.  Receiver TypeKinds
    // are populated by [`crate::ssa::type_facts::constructor_type`] for
    // `new Sequelize(...)` / `getRepository(...)` / `getManager()` /
    // `createEntityManager()`; the type-qualified resolver rewrites
    // `<recv>.<method>` → `<TypePrefix>.<method>` against these matchers.
    LabelRule {
        matchers: &[
            "Sequelize.literal",
            "TypeOrmRepo.query",
            "TypeOrmRepo.createQueryBuilder",
            "TypeOrmManager.query",
            "TypeOrmManager.createQueryBuilder",
            "MikroOrmEm.execute",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // ─── LDAP injection sinks ───
    //
    // Mirror of `labels/javascript.rs`; ldapjs / ts-ldapjs has the same
    // `client.search(...)` shape.  Type-qualified resolution covers both
    // `const client = ldap.createClient({...}); client.search(...)` (bound
    // variable, type forwarded from the parent body via
    // [`crate::taint::inject_external_type_facts`]) and the chained
    // `ldap.createClient({...}).search(...)` form.
    LabelRule {
        matchers: &["LdapClient.search"],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── LDAP-filter sanitizers ───
    LabelRule {
        matchers: &[
            "ldapEscape",
            "ldap-escape",
            "ldapescape.filter",
            "ldapescape.dn",
        ],
        label: DataLabel::Sanitizer(Cap::LDAP_INJECTION),
        case_sensitive: false,
    },
    // ─── XPath injection sinks ───  (mirrors `labels/javascript.rs`)
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
    // ─── XPath escape sanitizers ───  (mirrors `labels/javascript.rs`)
    LabelRule {
        matchers: &["escapeXpath", "xpathEscape", "escape_xpath"],
        label: DataLabel::Sanitizer(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF injection sinks ───  (mirrors `labels/javascript.rs`)
    LabelRule {
        matchers: &["setHeader", "res.set", "res.header", "res.append"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // Subscript-set form (mirrors `labels/javascript.rs`).
    LabelRule {
        matchers: &["res.headers", "response.headers", "self.response.headers"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF sanitizers ───  (mirrors `labels/javascript.rs`)
    LabelRule {
        matchers: &["stripCRLF", "stripCrlf", "escapeHeader", "sanitizeHeader"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Prototype pollution sinks ───  (mirrors `labels/javascript.rs`)
    //
    // Argument-role gating is enforced via Destination activation in
    // `GATED_SINKS` below: only taint flowing into source-object
    // arguments (positions 1+) activates; tainted-target alone is
    // benign.  Flat rules here are intentionally empty for the merge
    // family.
    // ─── Open redirect sinks ───  (mirrors `labels/javascript.rs`)
    LabelRule {
        matchers: &[
            "res.redirect",
            "location.replace",
            "location.assign",
            "window.open",
            "router.navigate",
            "router.navigateByUrl",
            "window.location",
            "window.location.href",
            "location.href",
        ],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
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
    // ─── SSTI sinks ───  (mirrors `labels/javascript.rs`; `_.template`
    // and `nunjucks.renderString` excluded — gated classifiers in
    // GATED_SINKS)
    LabelRule {
        matchers: &["Handlebars.compile"],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: false,
    },
    // ─── XXE sinks ───  (mirrors `labels/javascript.rs`)
    LabelRule {
        matchers: &["libxmljs.parseXmlString", "libxmljs.parseXml"],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
    },
];

/// Callee patterns that must never be classified as source/sanitizer/sink.
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
    // Dockerode container API — see javascript.rs EXCLUDES for rationale.
    "container.exec",
    "exec.start",
];

/// Phase 05 — `node:fs/promises` path-traversal sinks. See
/// `javascript.rs::GATED_LABEL_RULES` for the design rationale; both
/// language registries carry the same matcher list to keep .ts and .js
/// fixtures in lockstep.
pub static GATED_LABEL_RULES: &[GatedLabelRule] = &[
    super::javascript::FS_PROMISES_IMPORT_PATH_RULE,
    super::javascript::FS_PROMISES_IMPORT_PATH_PAIR_RULE,
    // Node core modules reached through an import binding; shared with
    // javascript.rs, which documents each rule.
    super::javascript::CHILD_PROCESS_IMPORT_RULE,
    super::javascript::VM_IMPORT_RULE,
    super::javascript::FS_IMPORT_PATH_RULE,
    super::javascript::FS_IMPORT_PATH_PAIR_RULE,
    // Phase 07 — Knex bare-name raw-SQL escape hatches. See
    // `labels/javascript.rs::GATED_LABEL_RULES` for the rationale; this
    // mirror keeps `.ts` and `.js` fixtures in lockstep.
    GatedLabelRule {
        matchers: &["whereRaw", "orderByRaw", "havingRaw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        gate: LabelGate::FileImportsModuleAsLocalName {
            modules: &["knex"],
            local_names: &["knex"],
        },
        payload_args: &[],
    },
    // Phase 07: Drizzle `sql.raw(...)`.  See
    // `labels/javascript.rs::GATED_LABEL_RULES`: the `sql` tag binds its
    // substitutions as parameters and is not a sink.
    GatedLabelRule {
        matchers: &["sql.raw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        gate: LabelGate::ImportedFromModule(&["drizzle-orm"]),
        payload_args: &[],
    },
    // Phase 10 — Next.js `cookies()` / `headers()` helpers from the
    // `next/headers` module return adversary-controlled
    // request-bound state (cookies carry session tokens, headers
    // carry auth material).  Gated on the import so app-internal
    // helpers named `cookies` or `headers` keep their default
    // classification.
    GatedLabelRule {
        matchers: &["cookies", "headers"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: true,
        gate: LabelGate::ImportedFromModule(&["next/headers"]),
        payload_args: &[],
    },
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
    // ── Lodash `_.template` SSTI/RCE gates, mirrors `labels/javascript.rs` ─
    // (Strapi CVE-2023-22621 class).  Lodash compiles `<% ... %>` evaluate
    // blocks into a JS Function; gate on the `evaluate` option and fire
    // conservatively when missing/dynamic.
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
    // ── XML XXE gates, mirrors `labels/javascript.rs` ────────────────────
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
    // ── Outbound HTTP clients (SSRF), see javascript.rs for rationale ────
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
    // Nuxt / Nitro `$fetch` and `ofetch` take the same `(url, init)` shape as
    // `fetch`; `$fetch` is not `.`-bounded so the plain `fetch` gate misses it.
    SinkGate {
        callee_matcher: "$fetch",
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
    SinkGate {
        callee_matcher: "ofetch",
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
    // `request` npm library: `request.get(url)` / `request.post(url, …)`.
    // Destination gate fires only on a tainted URL arg. Mirrors javascript.rs.
    SinkGate {
        callee_matcher: "request.get",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["url", "uri"],
        },
    },
    SinkGate {
        callee_matcher: "request.post",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["url", "uri"],
        },
    },
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
    // Node `http.get` / `https.get` convenience wrappers around `.request()`.
    // Same destination semantics. Motivated by CVE-2025-64430 (Parse Server
    // SSRF via http.get(uri)). Mirrors `labels/javascript.rs`.
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
    // `fetch(input, init)`, payload-bearing fields of `init` (arg 1) flow
    // into the request body / headers / json, distinct from SSRF on the URL
    // (arg 0).  See javascript.rs for full rationale.
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
    // See javascript.rs for the rationale.  Only arg 0 (command string or
    // binary) carries the shell-injection payload.  The qualified gates
    // restrict the flat `child_process.*` sinks; bare forms use `=`
    // exact-only matching so they don't collide with any `<receiver>.exec`
    // method.
    SinkGate::payload_positions(
        "child_process.exec",
        DataLabel::Sink(Cap::SHELL_ESCAPE),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "child_process.execSync",
        DataLabel::Sink(Cap::SHELL_ESCAPE),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "child_process.execFile",
        DataLabel::Sink(Cap::SHELL_ESCAPE),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "child_process.execFileSync",
        DataLabel::Sink(Cap::SHELL_ESCAPE),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "child_process.spawn",
        DataLabel::Sink(Cap::SHELL_ESCAPE),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "child_process.spawnSync",
        DataLabel::Sink(Cap::SHELL_ESCAPE),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "child_process.fork",
        DataLabel::Sink(Cap::SHELL_ESCAPE),
        true,
        &[0],
    ),
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
    // See javascript.rs for rationale.
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
    // ── Raw-SQL query builders with a trailing bind/options argument ─────
    //
    // Mirror of `labels/javascript.rs`.  `sequelize.query(sql, options)`,
    // `knex.raw(sql, bindings)`, and the mysql/pg driver methods take the SQL
    // string at arg 0 and a separate bind-params / options / callback at arg
    // 1+.  Only arg 0 is the injection vector; propagate `payload_args: &[0]`
    // onto the flat sink so the migration idiom
    // `queryInterface.sequelize.query(constDDL, { transaction })` (constant
    // SQL, non-constant options object) no longer FPs `cfg-unguarded-sink`.
    SinkGate {
        callee_matcher: "sequelize.query",
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
        callee_matcher: "knex.raw",
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
        callee_matcher: "connection.query",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: super::javascript::SQL_DRIVER_TEXT_FIELDS,
        },
    },
    SinkGate {
        callee_matcher: "client.query",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: super::javascript::SQL_DRIVER_TEXT_FIELDS,
        },
    },
    SinkGate {
        callee_matcher: "pool.query",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: super::javascript::SQL_DRIVER_TEXT_FIELDS,
        },
    },
    SinkGate {
        callee_matcher: "db.query",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: super::javascript::SQL_DRIVER_TEXT_FIELDS,
        },
    },
    SinkGate::payload_positions("db.exec", DataLabel::Sink(Cap::SQL_QUERY), false, &[0]),
    SinkGate {
        callee_matcher: "db.execute",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: super::javascript::SQL_DRIVER_TEXT_FIELDS,
        },
    },
    // `nunjucks.renderString(src, ctx)` — Nunjucks SSTI sink.  Only the
    // template *source* (arg 0) lets an attacker drive template
    // execution; the `ctx` data object (arg 1) is rendered via the
    // template's escape policy and is not itself a code-injection
    // vector.  Gate via Destination-style activation with
    // `payload_args: &[0]` so taint flowing only into `ctx` is
    // suppressed.  Mirrors `labels/javascript.rs`.
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
    // Mirrors `labels/javascript.rs` GATED_SINKS proto-pollution block.
    // Argument-role gating: `(target, src1, src2, ...)`, only source
    // positions trigger.  See the JS module for the rationale and the
    // `payload_args` width choice.
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
    // Prototype targets only; see `javascript::SHALLOW_ASSIGN_MERGES`.
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
    // Bare `extend` (suffix-matched) — see labels/javascript.rs for full
    // rationale.  `LiteralOnly` activation requires arg 0 to be literal `true`
    // so Backbone's `Model.extend({proto})` class-extension form does not
    // fire (its arg 0 is an object literal, not a boolean).
    SinkGate {
        callee_matcher: "extend",
        arg_index: 0,
        dangerous_values: &["true"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::PROTOTYPE_POLLUTION),
        case_sensitive: true,
        payload_args: &[2, 3, 4, 5],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::LiteralOnly,
    },
    // `set-value` standalone helper (CVE-2019-10747 / CVE-2021-23440) —
    // recursive set-by-path helper that did not block `__proto__` keys.
    // Mirrors `labels/javascript.rs`.
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
    // CVE-2020-8116.  Mirrors `labels/javascript.rs`.
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
    // `jsonpath` / `jsonpath-plus` `jp.set(obj, path, value)` family —
    // mirrors `labels/javascript.rs`.
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
    // ── Express / Node `http` response payload positions ─────────────────
    // See javascript.rs: keeps the `res` receiver out of the payload.
    // `res.json` is intentionally absent: see the note on the `res.send` rule.
    SinkGate::payload_positions("res.send", DataLabel::Sink(Cap::HTML_ESCAPE), false, &[0]),
    SinkGate::payload_positions(
        "res.redirect",
        DataLabel::Sink(Cap::OPEN_REDIRECT),
        false,
        &[0, 1],
    ),
    SinkGate::payload_positions(
        "res.set",
        DataLabel::Sink(Cap::HEADER_INJECTION),
        false,
        &[0, 1],
    ),
    SinkGate::payload_positions(
        "res.header",
        DataLabel::Sink(Cap::HEADER_INJECTION),
        false,
        &[0, 1],
    ),
    SinkGate::payload_positions(
        "res.append",
        DataLabel::Sink(Cap::HEADER_INJECTION),
        false,
        &[0, 1],
    ),
    SinkGate::payload_positions(
        "setHeader",
        DataLabel::Sink(Cap::HEADER_INJECTION),
        false,
        &[0, 1],
    ),
    SinkGate::payload_positions("res.sendFile", DataLabel::Sink(Cap::FILE_IO), false, &[0]),
    SinkGate::payload_positions("res.download", DataLabel::Sink(Cap::FILE_IO), false, &[0]),
    // ── String-evaluating timers ─────────────────────────────────────────
    //
    // `setTimeout(code, ms)` / `setInterval(code, ms)` compile a string
    // first argument like `eval`.  The usual argument is a callback, so the
    // CFG gate pass keeps these gates only when arg 0 is a string by
    // construction (see `STRING_EVALUATING_TIMERS`).  Exact-only (`=`) so
    // `socket.setTimeout(ms)` / `req.setTimeout(ms)` never match.
    SinkGate::payload_positions("=setTimeout", DataLabel::Sink(Cap::CODE_EXEC), true, &[0]),
    SinkGate::payload_positions("=setInterval", DataLabel::Sink(Cap::CODE_EXEC), true, &[0]),
    SinkGate::payload_positions(
        "window.setTimeout",
        DataLabel::Sink(Cap::CODE_EXEC),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "window.setInterval",
        DataLabel::Sink(Cap::CODE_EXEC),
        true,
        &[0],
    ),
    // ── Query-builder raw SQL text (TypeORM / MikroORM) ──────────────────
    // See javascript.rs.
    SinkGate::payload_positions(
        "QueryBuilder.where",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.andWhere",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.orWhere",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.having",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.andHaving",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.orHaving",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.orderBy",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.addOrderBy",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.groupBy",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.addGroupBy",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.select",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "QueryBuilder.addSelect",
        DataLabel::Sink(Cap::SQL_QUERY),
        true,
        &[0],
    ),
    // ── `vm` code compilation and `fs.appendFile` payload positions ──────
    SinkGate::payload_positions(
        "vm.runInNewContext",
        DataLabel::Sink(Cap::CODE_EXEC),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "vm.runInThisContext",
        DataLabel::Sink(Cap::CODE_EXEC),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "vm.runInContext",
        DataLabel::Sink(Cap::CODE_EXEC),
        true,
        &[0],
    ),
    SinkGate::payload_positions(
        "vm.compileFunction",
        DataLabel::Sink(Cap::CODE_EXEC),
        true,
        &[0],
    ),
    SinkGate::payload_positions("vm.Script", DataLabel::Sink(Cap::CODE_EXEC), true, &[0]),
    SinkGate::payload_positions("fs.appendFile", DataLabel::Sink(Cap::FILE_IO), false, &[0]),
    SinkGate::payload_positions(
        "fs.appendFileSync",
        DataLabel::Sink(Cap::FILE_IO),
        false,
        &[0],
    ),
    // ── `fs` write payload positions ─────────────────────────────────────
    //
    // Path traversal needs taint in the path.  The written content (arg 1)
    // and the options object are not traversal vectors, so logging request
    // data to a fixed file is not a FILE_IO finding.
    SinkGate::payload_positions("fs.writeFile", DataLabel::Sink(Cap::FILE_IO), false, &[0]),
    SinkGate::payload_positions(
        "fs.writeFileSync",
        DataLabel::Sink(Cap::FILE_IO),
        false,
        &[0],
    ),
    SinkGate::payload_positions(
        "fs.createWriteStream",
        DataLabel::Sink(Cap::FILE_IO),
        false,
        &[0],
    ),
    SinkGate::payload_positions(
        "fs.promises.writeFile",
        DataLabel::Sink(Cap::FILE_IO),
        false,
        &[0],
    ),
    SinkGate::payload_positions(
        "fs.promises.appendFile",
        DataLabel::Sink(Cap::FILE_IO),
        false,
        &[0],
    ),
    SinkGate::payload_positions(
        "FileSystemPromisesNs.writeFile",
        DataLabel::Sink(Cap::FILE_IO),
        false,
        &[0],
    ),
    SinkGate::payload_positions(
        "FileSystemPromisesNs.appendFile",
        DataLabel::Sink(Cap::FILE_IO),
        false,
        &[0],
    ),
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
    "switch_statement"              => Kind::Switch,
    "switch_body"                   => Kind::Block,
    "switch_case"                   => Kind::Block,
    "switch_default"                => Kind::Block,
    "try_statement"                 => Kind::Try,
    "catch_clause"                  => Kind::Block,
    "finally_clause"                => Kind::Block,
    "class_declaration"             => Kind::Block,
    "class"                         => Kind::Block,
    "class_body"                    => Kind::Block,
    "abstract_class_declaration"    => Kind::Block,
    "export_statement"              => Kind::Block,
    "enum_declaration"              => Kind::Trivia,

    // data-flow
    "call_expression"       => Kind::CallFn,
    "new_expression"        => Kind::CallFn,
    "assignment_expression" => Kind::Assignment,
    // `x += y`, `x ??= y`: read-modify-write, see `cfg::rmw_assignment`.
    "augmented_assignment_expression" => Kind::Assignment,
    // `i++` / `--i`: read-modify-write, see `cfg::rmw_assignment`.
    "update_expression"     => Kind::Assignment,
    "variable_declaration"  => Kind::CallWrapper,
    "lexical_declaration"   => Kind::CallWrapper,
    "expression_statement"  => Kind::CallWrapper,
    "as_expression"         => Kind::Seq,
    "type_assertion"        => Kind::Seq,
    "await_expression"      => Kind::AwaitForward,
    "jsx_attribute"         => Kind::JsxAttr,

    // trivia
    "comment"               => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_statement"      => Kind::Trivia,
    "type_alias_declaration" => Kind::Trivia,
    "interface_declaration" => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["required_parameter", "optional_parameter", "identifier"],
    self_param_kinds: &[],
    ident_fields: &["name", "pattern"],
};

/// Framework-conditional rules for TypeScript.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    // Astro endpoints read request data from the `APIContext` (`ctx` /
    // `context`) or the `Astro` global.  `url.origin` and `url.host` are left
    // out: the site's own origin is not attacker input.
    if ctx.has(DetectedFramework::Astro) {
        rules.push(RuntimeLabelRule {
            matchers: [
                "url.searchParams",
                "url.search",
                "url.pathname",
                "request",
                "params",
            ]
            .iter()
            .flat_map(|leaf| {
                ["ctx", "context", "Astro"]
                    .iter()
                    .map(move |root| format!("{root}.{leaf}"))
            })
            .collect(),
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
    }

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
        // `ctx.body` is an alias of `ctx.response.body`; both are written
        // as assignment targets.
        rules.push(RuntimeLabelRule {
            matchers: vec!["ctx.body".into(), "ctx.response.body".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
        // A redirect sends the browser elsewhere: open redirect, not SSRF.
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "ctx.redirect".into(),
                "ctx.response.redirect".into(),
                // Koa's own response prototype redirects through `this`.
                "this.redirect".into(),
            ],
            label: DataLabel::Sink(Cap::OPEN_REDIRECT),
            case_sensitive: false,
        });
        // Header setters write a response header, so the risk is CRLF
        // injection; HTML escaping does nothing for them.
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "ctx.set".into(),
                "ctx.append".into(),
                "ctx.response.set".into(),
                "ctx.response.append".into(),
            ],
            label: DataLabel::Sink(Cap::HEADER_INJECTION),
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
            label: DataLabel::Sink(Cap::OPEN_REDIRECT),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["reply.sendFile".into(), "reply.download".into()],
            label: DataLabel::Sink(Cap::FILE_IO),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["reply.header".into(), "reply.headers".into()],
            label: DataLabel::Sink(Cap::HEADER_INJECTION),
            case_sensitive: false,
        });
    }

    rules
}
