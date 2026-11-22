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
    // the SSA receiver carries `TypeKind::Request` and the
    // type-qualified resolver rewrites `req.json()` → `Request.json`
    // etc.  Mirrors the matching list in `labels/typescript.rs`.
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
    // Dynamic code construction.  `=Function` is exact-only so it covers
    // `new Function(src)` and `Function(src)` (the `new_expression`
    // constructor text is `Function`) without matching `x.Function`.  Every
    // argument of the Function constructor is compiled (parameter names and
    // body alike), so it stays unrestricted.  The `vm` entry points compile
    // arg 0 only; their `GATED_SINKS` entries keep the sandbox / options
    // object out of the payload.  Destructured `vm` imports ride
    // `GATED_LABEL_RULES`.
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
    // flat: a bare `exec` suffix also matched `RegExp.prototype.exec`,
    // mongoose `Query.exec()` and sqlite `db.exec(sql)`.  The other shapes
    // are resolved through the file's imports instead:
    //
    //   * `cp.exec(cmd)` with `cp = require('child_process')` and the
    //     destructured `const { exec } = require('child_process')` form ride
    //     the `ImportedFromModule` rule in `GATED_LABEL_RULES`.
    //   * `require('child_process').exec(cmd)` is rewritten to
    //     `child_process.exec` by the CFG callee canonicaliser.
    //   * the bare `=exec` / `=execSync` / `=execFile` gates in `GATED_SINKS`
    //     keep firing on destructured calls inside function scopes, which
    //     the top-level import view does not see.
    //
    // Only arg 0 (the command or binary) is a payload; the `GATED_SINKS`
    // entries below restrict the flat sink accordingly.  The argv-taking
    // forms (`execFile`, `spawn`, ...) also treat the argv array as a payload
    // when the options object enables `shell` (see
    // `CHILD_PROCESS_SHELL_OPTION_METHODS`).
    LabelRule {
        matchers: &[
            "child_process.exec",
            "child_process.execSync",
            "child_process.execFile",
            "child_process.execFileSync",
            "child_process.spawn",
            "child_process.spawnSync",
            "child_process.fork",
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
    // Express response sinks.  Each response method has a matching
    // `GATED_SINKS` entry that restricts the payload to the body / header /
    // path args, so taint on the `res` object itself (a `res.locals.x = ...`
    // field write, a fetch `Response` named `res`) never counts as the
    // written value.  Fluent chains such as `res.status(404).send(body)`
    // reach these rules through the CFG callee canonicaliser, which rewrites
    // them to `res.send`.
    // JSON responses (`res.json`, a Koa `ctx.body` object or array literal) are
    // not modelled as direct XSS sinks: they are sent with
    // `Content-Type: application/json`, which browsers do not render as HTML.
    LabelRule {
        matchers: &["res.send"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // `res.redirect` is OPEN_REDIRECT only (see the dedicated rule below): a
    // 302 to the browser is client-side navigation, not SSRF.
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
            // Two-path forms: both the source and the destination are paths.
            "fs.rename",
            "fs.renameSync",
            "fs.copyFile",
            "fs.copyFileSync",
            // Arg 1 is the appended data, not a path; the `GATED_SINKS`
            // entries restrict these to arg 0.
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
            // better-sqlite3 / sqlite3 `db.exec(sql)` runs a raw SQL string.
            // (A bare `exec` suffix used to classify it as a shell sink.)
            "db.exec",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // ORM / query builder raw-SQL entry points.
    //
    // `$queryRaw` / `$executeRaw` are flat sinks for the call form, but the
    // tagged-template form (`prisma.$queryRaw\`... ${x}\``) sends every
    // substitution as a bind parameter.  The CFG limits the tagged form to
    // substitutions that splice raw text (`${Prisma.raw(x)}`), see
    // `cfg::apply_js_sql_template_params`.
    //
    // `$queryRawUnsafe` / `$executeRawUnsafe` accept positional bind
    // parameters: `tx.$queryRawUnsafe(sqlTemplate, p1, p2, ...)` binds
    // p1..pN as `$1..$N` (PostgreSQL prepared-statement params) and the SQL
    // template at arg 0 is the only injection point.  These are modeled as
    // gated sinks below (`payload_args: &[0]`) so taint flowing only into
    // the bind params no longer fires.  `sequelize.query` and `knex.raw`
    // also accept a separate bind-params object/array at arg 1 (Sequelize's
    // `{ replacements, bind, type, transaction }` options object, knex's
    // positional `?`-binding array), so they are ALSO gated with
    // `payload_args: &[0]` below to restrict injection to the SQL string.
    LabelRule {
        matchers: &["sequelize.query", "knex.raw", "$queryRaw", "$executeRaw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // ── Phase 07 — ORM query-builder receiver-typed sinks ──
    //
    // Each rule here matches a callee text constructed by
    // `resolve_type_qualified_labels` when a value's inferred TypeKind has a
    // `label_prefix()`.  The matcher form `<TypePrefix>.<method>` is the
    // wire shape produced by that helper.  The receiver TypeKinds
    // themselves are populated by [`crate::ssa::type_facts::constructor_type`]
    // (TS/JS branch): `new Sequelize(...)` → `Sequelize`,
    // `getRepository(Entity)` → `TypeOrmRepo`,
    // `getManager()` → `TypeOrmManager`,
    // `createEntityManager()` → `MikroOrmEm`.  Without a typed receiver the
    // qualified callee text is never built, so these rules cannot misfire on
    // unrelated `.literal()` / `.query()` / `.execute()` methods.
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
        matchers: &[
            "ldapEscape",
            "ldap-escape",
            "ldapescape.filter",
            "ldapescape.dn",
        ],
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
        matchers: &["res.headers", "response.headers", "self.response.headers"],
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
    // navigation: `location.replace` / `location.assign` / `window.open`
    // fire as direct calls.  They navigate the user's browser, so they are
    // open redirects, not SSRF: the server never fetches the URL.
    // `window.location = url` / `window.location.href = url` /
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
    // the follow-on stream attach.  The built-in shell rules no longer
    // suffix-match a bare `exec`, but a broad custom `exec` rule still
    // would, so both stay excluded.  These patterns name the Dockerode SDK
    // methods specifically; if a project happens to also expose its own
    // `container.exec` shell wrapper, override via
    // [analysis.languages.javascript] custom rules.
    "container.exec",
    "exec.start",
];

/// Express / Fastify response methods that return the response object, so
/// `res.status(404).send(body)` sends through `res.send`.  The CFG callee
/// canonicaliser (`cfg::helpers::js_canonical_callee`) collapses a chain to
/// `{root}.{last method}` only when every intermediate link is listed here;
/// any other link keeps the chain's own text.
pub(crate) const FLUENT_RESPONSE_METHODS: &[&str] = &[
    "status",
    "type",
    "contentType",
    "set",
    "header",
    "headers",
    "append",
    "cookie",
    "clearCookie",
    "vary",
    "location",
    "links",
    "attachment",
    "code",
    "removeHeader",
];

/// TypeORM / MikroORM `QueryBuilder` methods that return the builder, so
/// `repo.createQueryBuilder('u').leftJoin(..).where(cond)` calls `where` on
/// the builder.  The CFG callee canonicaliser rewrites such chains to
/// `QueryBuilder.<method>` (`cfg::helpers::js_canonical_callee`).
pub(crate) const QUERY_BUILDER_CHAIN_METHODS: &[&str] = &[
    "select",
    "addSelect",
    "from",
    "where",
    "andWhere",
    "orWhere",
    "having",
    "andHaving",
    "orHaving",
    "orderBy",
    "addOrderBy",
    "groupBy",
    "addGroupBy",
    "leftJoin",
    "leftJoinAndSelect",
    "innerJoin",
    "innerJoinAndSelect",
    "leftJoinAndMapOne",
    "leftJoinAndMapMany",
    "innerJoinAndMapOne",
    "innerJoinAndMapMany",
    "setParameter",
    "setParameters",
    "skip",
    "take",
    "limit",
    "offset",
    "withDeleted",
    "distinct",
    "distinctOn",
    "cache",
    "setLock",
    "useTransaction",
];

/// Query-builder methods that put their first argument into the SQL text
/// verbatim: a condition string (`where("u.name = '" + x + "'")`), a column
/// or expression (`orderBy(x)`, `select(x)`).  Bind values go in the
/// separate parameters object (arg 1), and an object, `Brackets` or
/// callback first argument is built by the ORM from parameters; the CFG gate
/// pass drops the sink for those shapes.
pub(crate) const QUERY_BUILDER_SQL_TEXT_METHODS: &[&str] = &[
    "where",
    "andWhere",
    "orWhere",
    "having",
    "andHaving",
    "orHaving",
    "orderBy",
    "addOrderBy",
    "groupBy",
    "addGroupBy",
    "select",
    "addSelect",
];

/// Timers that compile a string first argument (`setTimeout('run()', 10)`).
/// Their `GATED_SINKS` entries only apply when arg 0 is a string by
/// construction (`cfg::literals::js_arg_is_string_valued`): a callback
/// argument, the normal case, compiles nothing.
pub(crate) const STRING_EVALUATING_TIMERS: &[&str] = &["setTimeout", "setInterval"];

/// Shallow merges that copy own properties with plain `[[Set]]`
/// (`Object.assign(target, ...sources)`).  A `__proto__` key in a source
/// only swaps `target`'s own prototype; `Object.prototype` stays untouched.
/// The call can therefore pollute a shared prototype only when `target`
/// already is one (`Object.assign(Foo.prototype, src)`), and the CFG gate
/// pass keeps their `PROTOTYPE_POLLUTION` gates for that shape alone
/// (`cfg::literals::js_arg_is_prototype_object`).
pub(crate) const SHALLOW_ASSIGN_MERGES: &[&str] = &["Object.assign"];

/// SQL text fields of the driver config-object call form:
/// `pool.query({ text, values, name })` (pg) and
/// `connection.query({ sql, values, timeout })` (mysql / mysql2).  The
/// `values` array is bound as parameters, so when arg 0 is an object
/// literal only these fields carry injectable SQL.  Any other object
/// (Apollo's `client.query({ query, variables })`) has none.
pub(crate) const SQL_DRIVER_TEXT_FIELDS: &[&str] = &["text", "sql"];

/// Node `child_process` entry points that spawn a process.  Shared by the
/// JS and TS import-gated shell rules.
pub(crate) const CHILD_PROCESS_METHODS: &[&str] = &[
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
    "fork",
];

/// The `child_process` methods that take an argv array and honour a
/// `shell` option.  Without `shell` the argv elements reach the program
/// verbatim, so only the binary (arg 0) is a shell payload.  With
/// `{ shell: true }` (or any non-false value) Node joins the binary and
/// argv into one `/bin/sh -c` string, which makes the argv array a payload
/// too.  `exec` / `execSync` always use a shell but take no argv, and
/// `fork` takes no `shell` option.
pub(crate) const CHILD_PROCESS_SHELL_OPTION_METHODS: &[&str] =
    &["execFile", "execFileSync", "spawn", "spawnSync"];

/// `child_process` through an import binding: the namespace alias
/// (`const cp = require('child_process'); cp.exec(cmd)`) and the
/// destructured bare name (`const { spawn } = require('node:child_process')`).
/// The gate checks the call's leading identifier against the file's
/// imports, so `re.exec(s)`, `User.find().exec()`, `db.exec(sql)` and
/// redux-saga's `fork(saga)` stay unlabelled.  Arg 0 is the command or
/// binary; the CFG post-pass widens the argv-taking forms when their options
/// enable `shell` (see [`CHILD_PROCESS_SHELL_OPTION_METHODS`]).
pub(crate) const CHILD_PROCESS_IMPORT_RULE: GatedLabelRule = GatedLabelRule {
    matchers: CHILD_PROCESS_METHODS,
    label: DataLabel::Sink(Cap::SHELL_ESCAPE),
    case_sensitive: true,
    gate: LabelGate::ImportedFromModule(&["child_process", "node:child_process"]),
    payload_args: &[0],
};

/// `vm` through an import binding (`const { runInNewContext } =
/// require('vm')`, `import * as nodeVm from 'node:vm'`).  Arg 0 is the
/// compiled source; the context / options object is not.
pub(crate) const VM_IMPORT_RULE: GatedLabelRule = GatedLabelRule {
    matchers: &[
        "runInNewContext",
        "runInThisContext",
        "runInContext",
        "compileFunction",
        "Script",
    ],
    label: DataLabel::Sink(Cap::CODE_EXEC),
    case_sensitive: true,
    gate: LabelGate::ImportedFromModule(&["vm", "node:vm"]),
    payload_args: &[0],
};

/// Callback and sync `fs` APIs through an import binding
/// (`import { readFileSync } from 'node:fs'`, `const fsx = require('fs')`).
/// Only the path is a payload: the data written by `writeFile` /
/// `appendFile` is not a traversal vector.  A call the flat `fs.*` rules
/// already label keeps its flat payload set; the CFG post-pass applies these
/// positions only where the import binding is what makes the call a sink.
pub(crate) const FS_IMPORT_PATH_RULE: GatedLabelRule = GatedLabelRule {
    matchers: &[
        "readFile",
        "readFileSync",
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "createReadStream",
        "createWriteStream",
        "access",
        "accessSync",
        "stat",
        "statSync",
        "open",
        "openSync",
        "readdir",
        "readdirSync",
        "mkdir",
        "mkdirSync",
        "rm",
        "rmSync",
        "rmdir",
        "rmdirSync",
        "unlink",
        "unlinkSync",
    ],
    label: DataLabel::Sink(Cap::FILE_IO),
    case_sensitive: true,
    gate: LabelGate::ImportedFromModule(&["fs", "node:fs"]),
    payload_args: &[0],
};

/// Two-path `fs` APIs through an import binding: both the source and the
/// destination are paths.
pub(crate) const FS_IMPORT_PATH_PAIR_RULE: GatedLabelRule = GatedLabelRule {
    matchers: &["rename", "renameSync", "copyFile", "copyFileSync"],
    label: DataLabel::Sink(Cap::FILE_IO),
    case_sensitive: true,
    gate: LabelGate::ImportedFromModule(&["fs", "node:fs"]),
    payload_args: &[0, 1],
};

/// `node:fs/promises` APIs through an import binding
/// (`import { writeFile } from 'node:fs/promises'`, `import * as fsp from
/// 'fs/promises'`).  Arg 0 is the path; the written data, mode and options
/// are not traversal vectors.
pub(crate) const FS_PROMISES_IMPORT_PATH_RULE: GatedLabelRule = GatedLabelRule {
    matchers: &[
        "readFile",
        "writeFile",
        "unlink",
        "open",
        "stat",
        "readdir",
        "mkdir",
        "rmdir",
        "rm",
        "appendFile",
        "truncate",
        "chmod",
    ],
    label: DataLabel::Sink(Cap::FILE_IO),
    case_sensitive: false,
    gate: LabelGate::ImportedFromModule(&["node:fs/promises", "fs/promises"]),
    payload_args: &[0],
};

/// Two-path `node:fs/promises` APIs: both the source and the destination are
/// paths.
pub(crate) const FS_PROMISES_IMPORT_PATH_PAIR_RULE: GatedLabelRule = GatedLabelRule {
    matchers: &["copyFile", "rename"],
    label: DataLabel::Sink(Cap::FILE_IO),
    case_sensitive: false,
    gate: LabelGate::ImportedFromModule(&["node:fs/promises", "fs/promises"]),
    payload_args: &[0, 1],
};

/// Phase 05 — `node:fs/promises` path-traversal sinks. The matcher list
/// holds the bare-name and `<ns>.<method>` member-access shapes; the
/// [`LabelGate::ImportedFromModule`] gate suppresses bare-name matches
/// unless the file actually imports the method from `node:fs/promises`
/// or `fs/promises`. Bare-name only — `fs.promises.readFile`-style
/// member-access forms continue to fire via the flat FILE_IO matcher
/// list (no gate needed because the `fs.promises.` prefix is itself
/// witness to the resolution).
pub static GATED_LABEL_RULES: &[GatedLabelRule] = &[
    FS_PROMISES_IMPORT_PATH_RULE,
    FS_PROMISES_IMPORT_PATH_PAIR_RULE,
    // Node core modules reached through an import binding.  Shared with
    // typescript.rs; see the constants for each rule's rationale.
    CHILD_PROCESS_IMPORT_RULE,
    VM_IMPORT_RULE,
    FS_IMPORT_PATH_RULE,
    FS_IMPORT_PATH_PAIR_RULE,
    // Phase 07 — Knex bare-name raw-SQL escape hatches. The receiver in
    // `db.whereRaw(sql)` shape is an arbitrary local binding (`db`, `qb`,
    // `users`, ...) so leading-identifier gating cannot witness the
    // import. Phase 07 deferred-item 10 tightening: require the file to
    // bind the conventional value-import name `knex` (lowercase) so that
    // type-only shapes like `import { Knex } from 'knex'` (for
    // `Knex.QueryBuilder` type annotations) do not over-fire the gate.
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
    // Phase 07: Drizzle `sql.raw(x)` splices `x` into the query text.  The
    // `sql\`SELECT ${x}\`` tag itself binds `x` as a parameter and is not a
    // sink; a `sql.raw` call inside it is found as a nested sink, and the
    // CFG treats the tag's result as SQL-safe
    // (`cfg::apply_js_sql_template_params`).  Gated on the `sql` import
    // from `drizzle-orm`.
    GatedLabelRule {
        matchers: &["sql.raw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        gate: LabelGate::ImportedFromModule(&["drizzle-orm"]),
        payload_args: &[],
    },
    // Phase 10 — Next.js `cookies()` / `headers()` from `next/headers`
    // return adversary-controlled request-bound state.  Mirrors the
    // entry in `labels/typescript.rs::GATED_LABEL_RULES`.
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
    // `request` npm library: `request.get(url)` / `request.post(url, …)`. The
    // Destination gate fires only on a tainted URL arg, so the `req.get(header)`
    // header-read collision (constant arg 0) never activates.
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
    // Only arg 0 (the command string or binary) is a shell-injection
    // payload.  `options.env` / `options.cwd` / an argv array / a callback at
    // arg 1+ are not.  The qualified `child_process.*` gates restrict the flat
    // sinks in RULES to arg 0.  Bare forms (`exec`, `execSync`, `execFile`,
    // `execAsync`, `execPromise`) use the `=` exact-only sigil so they match
    // the destructured-import shape (`const { exec } =
    // require('child_process'); exec(cmd)`) without colliding with any
    // `<receiver>.exec` method (Dockerode's `container.exec`,
    // `RegExp.prototype.exec`, etc.).
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
    // ── Raw-SQL query builders with a trailing bind/options argument ─────
    //
    // `sequelize.query(sql, options)`, `knex.raw(sql, bindings)`, and the
    // mysql/mysql2/pg/better-sqlite3 driver methods `connection.query`,
    // `client.query`, `pool.query`, `db.query`, `db.execute` all take the SQL
    // string at arg 0 and a *separate* bind-params / options argument at arg
    // 1+ (`{ replacements, bind, type, transaction }` for Sequelize, a
    // positional `?`-binding array for knex, a `values` array / callback for
    // the drivers).  Only arg 0 (the SQL template) is the injection vector;
    // the bind params are parameterised, and the options object is inert.
    // The flat `Sink(SQL_QUERY)` rules above cover the sink, but their
    // implicit "all args" model FPs on the extremely common migration idiom
    // `queryInterface.sequelize.query(constDDL, { transaction })`: the
    // constant SQL is provably non-injectable, yet the non-constant options
    // object at arg 1 defeats `cfg_analysis::guards::is_all_args_constant`
    // (whole-call) and re-opens `cfg-unguarded-sink`.  These gates propagate
    // `payload_args: &[0]` onto the flat sink (mirroring `$queryRawUnsafe`
    // above) so both the taint scan and the const-arg suppression restrict
    // to the SQL string.  Suffix-match (no `=` sigil) so
    // `queryInterface.sequelize.query`, `db.knex.raw`, `this.#db.knex.raw`,
    // etc. all qualify.  The driver gates also accept the config-object form
    // (`pool.query({ text, values })`), where only the SQL text fields are
    // payload (`SQL_DRIVER_TEXT_FIELDS`).
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
            object_destination_fields: SQL_DRIVER_TEXT_FIELDS,
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
            object_destination_fields: SQL_DRIVER_TEXT_FIELDS,
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
            object_destination_fields: SQL_DRIVER_TEXT_FIELDS,
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
            object_destination_fields: SQL_DRIVER_TEXT_FIELDS,
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
            object_destination_fields: SQL_DRIVER_TEXT_FIELDS,
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
    // `Object.assign(target, ...sources)` copies own properties without
    // recursing, so attacker input can only reach a shared prototype when
    // `target` is one (`Object.assign(Foo.prototype, req.body)`).  The CFG
    // gate pass drops this gate for any other target (see
    // `SHALLOW_ASSIGN_MERGES`); the target stays out of `payload_args`.
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
    // Bare `extend` (suffix-matched) for jQuery's deep form imported as a
    // bound name: `const { extend } = require('jquery'); extend(true, t, s)`.
    // Suffix `extend` would over-fire on Backbone's `Model.extend(proto)` /
    // `View.extend({...})` class-extension idiom, so this gate uses
    // `LiteralOnly` activation: it fires only when arg 0 is the literal
    // boolean `true` (the deep-flag form, never used by Backbone subclassing).
    // Sources start at arg 2 because arg 0 is the flag and arg 1 is the
    // target; tainting the target alone is benign.
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
    // ── Express / Node `http` response payload positions ─────────────────
    //
    // The flat response rules in RULES would otherwise fall back to every
    // operand of the call, receiver included.  `res` picks up taint from a
    // field write (`res.locals.q = req.query.q`) and client code often names
    // a fetch `Response` `res`, so a constant `res.send("ok")` or a
    // zero-arg `res.send()` was reported as XSS.  Body writers take the body
    // at arg 0; `res.redirect([status,] url)` and the header setters
    // (`res.set(name, value)`, `setHeader(name, value)`) take theirs at 0..1.
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
    //
    // `repo.createQueryBuilder('u').where(\`u.name = '${name}'\`)` and the
    // other `QUERY_BUILDER_SQL_TEXT_METHODS` reach these gates through the
    // `QueryBuilder.<method>` canonical callee.  Arg 0 is SQL text; the
    // parameters object at arg 1 is bound.  Gate-only (no flat rule) so the
    // CFG gate pass can drop the sink for an object / `Brackets` / callback
    // condition.
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
    //
    // `vm.runInNewContext(code, sandbox)` compiles arg 0; the sandbox and
    // options objects are data.  `fs.appendFile(path, data)` writes arg 1,
    // which is not a traversal vector.
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
    // `x += y`, `x ??= y`: read-modify-write, see `cfg::rmw_assignment`.
    "augmented_assignment_expression" => Kind::Assignment,
    // `i++` / `--i`: read-modify-write, see `cfg::rmw_assignment`.
    "update_expression"     => Kind::Assignment,
    "variable_declaration"  => Kind::CallWrapper,
    "lexical_declaration"   => Kind::CallWrapper,
    "expression_statement"  => Kind::CallWrapper,
    "await_expression"      => Kind::AwaitForward,
    "jsx_attribute"         => Kind::JsxAttr,

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

#[cfg(test)]
mod tests {
    use crate::labels::{
        Cap, ClassificationContext, DataLabel, classify_all, classify_gated_matches,
        classify_gated_sink,
    };
    use std::collections::HashMap;

    fn shell_sink(labels: &[DataLabel]) -> bool {
        labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SHELL_ESCAPE)))
    }

    fn gated_payload(lang: &str, callee: &str) -> Option<Vec<usize>> {
        let gates = classify_gated_sink(lang, callee, |_| None, |_| None, |_| false);
        gates.first().map(|g| g.payload_args.to_vec())
    }

    #[test]
    fn receiver_exec_methods_are_not_shell_sinks() {
        for lang in ["javascript", "typescript"] {
            for callee in [
                "re.exec",
                "/^Bearer (.+)$/.exec",
                "SEMVER.exec",
                "q.exec",
                "db.exec",
                "this.exec",
                "stmt.execSync",
            ] {
                assert!(
                    !shell_sink(&classify_all(lang, callee, None)),
                    "{lang}: `{callee}` must not be a flat shell sink"
                );
            }
            // sqlite `db.exec(sql)` runs SQL.
            assert!(
                classify_all(lang, "db.exec", None).contains(&DataLabel::Sink(Cap::SQL_QUERY)),
                "{lang}: db.exec should be a SQL sink"
            );
        }
    }

    #[test]
    fn qualified_child_process_forms_are_shell_sinks_on_arg_zero() {
        for lang in ["javascript", "typescript"] {
            for callee in [
                "child_process.exec",
                "child_process.execSync",
                "child_process.execFile",
                "child_process.execFileSync",
                "child_process.spawn",
                "child_process.spawnSync",
                "child_process.fork",
            ] {
                assert!(
                    shell_sink(&classify_all(lang, callee, None)),
                    "{lang}: `{callee}` should be a shell sink"
                );
                assert_eq!(
                    gated_payload(lang, callee),
                    Some(vec![0]),
                    "{lang}: {callee}"
                );
            }
        }
    }

    #[test]
    fn child_process_import_binding_gates_alias_and_destructured_calls() {
        let mut imports: HashMap<String, String> = HashMap::new();
        imports.insert("cp".into(), "child_process".into());
        imports.insert("spawn".into(), "node:child_process".into());
        imports.insert("fork".into(), "redux-saga/effects".into());
        imports.insert("re".into(), "./patterns".into());
        let ctx = ClassificationContext {
            local_imports: Some(&imports),
        };
        for lang in ["javascript", "typescript"] {
            for callee in ["cp.exec", "cp.spawnSync", "cp.fork", "spawn"] {
                let hits = classify_gated_matches(lang, callee, Some(&ctx));
                let hit = hits
                    .iter()
                    .find(|m| m.label == DataLabel::Sink(Cap::SHELL_ESCAPE))
                    .unwrap_or_else(|| panic!("{lang}: `{callee}` should be gated in"));
                assert_eq!(hit.payload_args, &[0], "{lang}: {callee}");
            }
            for callee in ["fork", "re.exec", "db.exec", "exec"] {
                let hits = classify_gated_matches(lang, callee, Some(&ctx));
                assert!(
                    hits.is_empty(),
                    "{lang}: `{callee}` is not bound to child_process, got {hits:?}"
                );
            }
        }
    }

    #[test]
    fn fs_import_binding_restricts_written_data() {
        let mut imports: HashMap<String, String> = HashMap::new();
        imports.insert("writeFileSync".into(), "node:fs".into());
        imports.insert("renameSync".into(), "fs".into());
        imports.insert("readFile".into(), "fs/promises".into());
        let ctx = ClassificationContext {
            local_imports: Some(&imports),
        };
        let write = classify_gated_matches("javascript", "writeFileSync", Some(&ctx));
        assert_eq!(write.len(), 1);
        assert_eq!(write[0].label, DataLabel::Sink(Cap::FILE_IO));
        assert_eq!(write[0].payload_args, &[0]);
        let rename = classify_gated_matches("typescript", "renameSync", Some(&ctx));
        assert_eq!(rename.len(), 1);
        assert_eq!(rename[0].payload_args, &[0, 1]);
        // fs/promises imports check the path alone, and both paths of a copy.
        let promises = classify_gated_matches("javascript", "readFile", Some(&ctx));
        assert_eq!(promises.len(), 1);
        assert_eq!(promises[0].payload_args, &[0]);
        imports.insert("copyFile".into(), "node:fs/promises".into());
        let ctx = ClassificationContext {
            local_imports: Some(&imports),
        };
        let copy = classify_gated_matches("typescript", "copyFile", Some(&ctx));
        assert_eq!(copy.len(), 1);
        assert_eq!(copy[0].payload_args, &[0, 1]);
        // The flat `fs.*` write sinks check the path, not the content.
        for callee in ["fs.writeFile", "fs.writeFileSync", "fs.promises.writeFile"] {
            assert_eq!(
                gated_payload("javascript", callee),
                Some(vec![0]),
                "{callee}"
            );
            assert_eq!(
                gated_payload("typescript", callee),
                Some(vec![0]),
                "{callee}"
            );
        }
    }

    #[test]
    fn function_constructor_and_vm_are_code_exec_sinks() {
        let code_exec = |labels: &[DataLabel]| {
            labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::CODE_EXEC)))
        };
        for lang in ["javascript", "typescript"] {
            for callee in [
                "Function",
                "vm.runInNewContext",
                "vm.Script",
                "vm.compileFunction",
            ] {
                assert!(
                    code_exec(&classify_all(lang, callee, None)),
                    "{lang}: {callee}"
                );
            }
            // `=Function` is exact-only: a method named Function is not the
            // global constructor.
            assert!(!code_exec(&classify_all(lang, "obj.Function", None)));
            assert_eq!(gated_payload(lang, "vm.runInNewContext"), Some(vec![0]));
        }
    }

    #[test]
    fn browser_navigation_is_open_redirect_not_ssrf() {
        for lang in ["javascript", "typescript"] {
            for callee in ["window.open", "location.assign", "location.replace"] {
                let labels = classify_all(lang, callee, None);
                assert!(
                    labels.contains(&DataLabel::Sink(Cap::OPEN_REDIRECT)),
                    "{lang}: {callee} -> {labels:?}"
                );
                assert!(
                    !labels
                        .iter()
                        .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SSRF))),
                    "{lang}: {callee} must not be SSRF, got {labels:?}"
                );
            }
            // Header setters are header-injection sinks only.
            for callee in ["res.set", "res.header"] {
                let labels = classify_all(lang, callee, None);
                assert!(
                    !labels
                        .iter()
                        .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::HTML_ESCAPE))),
                    "{lang}: {callee} must not be an XSS sink, got {labels:?}"
                );
            }
        }
    }

    #[test]
    fn sql_driver_gates_check_config_object_sql_text_only() {
        for lang in ["javascript", "typescript"] {
            for callee in [
                "pool.query",
                "client.query",
                "connection.query",
                "db.execute",
            ] {
                let gates = classify_gated_sink(lang, callee, |_| None, |_| None, |_| false);
                let sql = gates
                    .iter()
                    .find(|g| g.label == DataLabel::Sink(Cap::SQL_QUERY))
                    .unwrap_or_else(|| panic!("{lang}: {callee} gate"));
                assert_eq!(sql.payload_args, &[0]);
                assert_eq!(sql.object_destination_fields, &["text", "sql"]);
            }
        }
    }

    #[test]
    fn query_builder_text_methods_are_gated_sql_sinks() {
        for lang in ["javascript", "typescript"] {
            for callee in [
                "QueryBuilder.where",
                "QueryBuilder.andWhere",
                "QueryBuilder.orderBy",
                "QueryBuilder.select",
            ] {
                assert_eq!(
                    gated_payload(lang, callee),
                    Some(vec![0]),
                    "{lang}: {callee}"
                );
            }
            // The builder's terminal methods and bare `where` are not sinks.
            assert_eq!(gated_payload(lang, "QueryBuilder.getMany"), None);
            assert_eq!(gated_payload(lang, "where"), None);
        }
    }

    #[test]
    fn response_sinks_exclude_the_receiver() {
        for lang in ["javascript", "typescript"] {
            for (callee, payload) in [
                ("res.send", vec![0]),
                ("res.redirect", vec![0, 1]),
                ("res.set", vec![0, 1]),
                ("res.setHeader", vec![0, 1]),
                ("res.sendFile", vec![0]),
            ] {
                assert_eq!(
                    gated_payload(lang, callee),
                    Some(payload),
                    "{lang}: {callee}"
                );
            }
        }
    }
}
