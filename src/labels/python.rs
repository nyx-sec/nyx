use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["os.getenv", "os.environ"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "request.args",
            "request.form",
            "request.json",
            "request.headers",
            "request.cookies",
            "request.files",
            "request.data",
            "request.values",
            "request.environ",
            "request.url",
            "request.base_url",
            "request.host",
            "request.match_info",
            "request.rel_url",
            "request.query",
            "request.path",
            // Common alias: from flask import request as flask_request
            "flask_request.args",
            "flask_request.form",
            "flask_request.json",
            "flask_request.headers",
            "flask_request.cookies",
            "flask_request.files",
            "flask_request.data",
            "flask_request.values",
            // Flask request methods (method-call form of the attributes above)
            "request.get_data",
            "request.get_json",
            "flask_request.get_data",
            "flask_request.get_json",
            "input",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Session stores: session cookies / DRF / Django auth carry auth material
    // the operator did not intend to leak.  `infer_source_kind` maps `session`
    // callees to `SourceKind::Cookie` (Sensitive) so flowing into an outbound
    // request payload fires `DATA_EXFIL`.  Case-sensitive: lowercase `session`
    // here is the Flask global / Django request attribute; the capitalised
    // `requests.Session` constructor is a client object, not a source, and
    // must not be tagged.
    //
    // The matchers cover both attribute access (`request.session.user_id`,
    // resolved as the attribute text) and the bare `session.<method>`
    // pattern that follows `from flask import session`.  The `=session`
    // exact-match form fires only when the call is the bare top-level
    // `session(...)` so accidental field projections like
    // `obj.client.session` (Phase 2 chained-receiver lowering) don't get
    // mis-labelled as sources.
    LabelRule {
        matchers: &[
            "request.session",
            "flask_request.session",
            "flask.session",
            "django.contrib.sessions",
            "=session",
            "session.get",
            "session.pop",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: true,
    },
    // Django-specific sources (case-sensitive to avoid request.get() dict method FP)
    LabelRule {
        matchers: &[
            "request.GET",
            "request.POST",
            "request.META",
            "request.body",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["sys.argv"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["open"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "argparse.parse_args",
            "urllib.request.urlopen",
            "requests.get",
            "requests.post",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["html.escape", "cgi.escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["shlex.quote"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "bleach.clean",
            "markupsafe.escape",
            "django.utils.html.escape",
        ],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Type coercion sanitizers
    LabelRule {
        matchers: &["int", "float", "bool"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["urllib.parse.quote", "urllib.parse.quote_plus"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // SQLAlchemy bound-parameter sanitizer.  Values passed as keyword
    // arguments to `text("…:name…").bindparams(name=value)` are bound
    // by the driver, so injection cannot break out of the literal
    // context.  The accompanying SQL-string check (py.sqli.text_format)
    // already flags the `text(f"…")` shape at construction, so this
    // sanitizer only clears flow when the SQL is a literal and the
    // values reach the engine via bindparams.  Recognises both the
    // method form (`text(…).bindparams(...)`) and the bare call form.
    LabelRule {
        matchers: &["bindparams", ".bindparams"],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Path canonicalization
    LabelRule {
        matchers: &["os.path.abspath", "os.path.normpath"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    // Flask sinks
    LabelRule {
        matchers: &["render_template_string"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    // Jinja2 / string.Template, tainted template string enables SSTI
    LabelRule {
        matchers: &["Template"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["make_response"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["redirect"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Django sinks
    LabelRule {
        matchers: &["HttpResponse", "mark_safe"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Flask Markup, bypasses auto-escaping
    LabelRule {
        matchers: &["Markup"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["eval", "exec"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "os.system",
            "os.popen",
            "subprocess.check_output",
            "subprocess.check_call",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["cursor.execute", "cursor.executemany", "sqlalchemy.text"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Django ORM raw SQL execution
    LabelRule {
        matchers: &["objects.raw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // SQL injection: sqlite3 / SQLAlchemy / generic DB connection execute.
    LabelRule {
        matchers: &[
            "conn.execute",
            "connection.execute",
            "session.execute",
            "engine.execute",
            "db.execute",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "send_file",
            "send_from_directory",
            // aiohttp file response — sends file at the supplied path,
            // semantically identical to Flask's send_file (CVE-2024-23334).
            "FileResponse",
            "web.FileResponse",
            "aiohttp.web.FileResponse",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["os.path.realpath"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // Outbound HTTP — flat SSRF sinks for read-shaped methods (GET / HEAD)
    // that don't carry a body.  Body-bearing methods (POST / PUT / PATCH /
    // DELETE / request) are modelled via destination-aware gates in
    // GATED_SINKS so SSRF activation can be narrowed to the URL position
    // and the cross-boundary `DATA_EXFIL` cap can attach to body kwargs as
    // a separate gate.  `urllib.request.urlopen` stays flat: its argument
    // is a Request object whose payload-vs-URL split happens at
    // `urllib.request.Request` construction (gated below).
    LabelRule {
        matchers: &[
            "urllib.request.urlopen",
            "requests.get",
            "requests.head",
            "httpx.get",
            "httpx.head",
            "aiohttp.get",
            "aiohttp.head",
            "HttpClient.get",
            "HttpClient.head",
            "HttpClient.send",
        ],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "pickle.loads",
            "pickle.load",
            "yaml.load", // unsafe unless SafeLoader
            "yaml.unsafe_load",
            "yaml.full_load",
            "shelve.open",
        ],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
    // ─── LDAP injection sinks ───
    //
    // python-ldap exposes module-level `ldap.search_s` / `ldap.search_ext_s`
    // and method-style `conn.search_s(base, scope, filter)` after `conn =
    // ldap.initialize(url)`.  Suffix matching on the method names catches both
    // the qualified form (`ldap.search_s`, matched as a literal) and the
    // bound-receiver form (`conn.search_s` ends with `search_s`).  ldap3 uses
    // `Connection(server, ...)` whose `.search(...)` accepts a filter kwarg /
    // positional; receiver typing tags the connection as `TypeKind::LdapClient`
    // so type-qualified resolution rewrites `conn.search` → `LdapClient.search`.
    LabelRule {
        matchers: &[
            "ldap.search_s",
            "ldap.search_ext_s",
            "search_s",
            "search_ext_s",
            "LdapClient.search",
            "ldap3.Connection.search",
        ],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── LDAP-filter sanitizers ───
    //
    // python-ldap: `ldap.filter.escape_filter_chars(s)` and ldap3's
    // `ldap3.utils.conv.escape_filter_chars(s)` both apply RFC 4515 escaping
    // to filter metacharacters.  Suffix matching on `escape_filter_chars`
    // covers both the fully-qualified import and the bare-name destructured
    // import (`from ldap.filter import escape_filter_chars`).
    LabelRule {
        matchers: &[
            "escape_filter_chars",
            "ldap.filter.escape_filter_chars",
            "ldap3.utils.conv.escape_filter_chars",
        ],
        label: DataLabel::Sanitizer(Cap::LDAP_INJECTION),
        case_sensitive: false,
    },
    // ─── XPath injection sinks ───
    //
    // lxml: `tree.xpath(expr)` / `etree.XPath(expr)` accept an
    // attacker-influenceable expression string.  ElementTree's
    // `find` / `findall` / `findtext` accept the same kind of XPath subset
    // and admit injection when the path is built by string concatenation.
    // Suffix matching on the bare method names catches both
    // `lxml.etree._Element.xpath(...)` and `tree.xpath(...)` shapes.
    LabelRule {
        matchers: &[
            "xpath",
            "lxml.etree.XPath",
            "etree.XPath",
            "ElementTree.find",
            "ElementTree.findall",
            "ElementTree.findtext",
        ],
        label: DataLabel::Sink(Cap::XPATH_INJECTION),
        case_sensitive: true,
    },
    // ─── XPath escape sanitizers ───
    //
    // No standard library helper escapes XPath metacharacters; project-local
    // `escape_xpath` / `xpath_escape` are the developer-named equivalents.
    LabelRule {
        matchers: &["escape_xpath", "xpath_escape"],
        label: DataLabel::Sanitizer(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF injection sinks ───
    //
    // Flask / Werkzeug response APIs that write a single header value:
    // `response.headers.add(name, val)`, `response.set_cookie(name, val)`,
    // `response.headers[name] = val` (subscript-set is harder to track
    // textually; rely on the `add` / `set_cookie` entry points and the
    // explicit `Headers.add` form).
    LabelRule {
        matchers: &["headers.add", "headers.set", "set_cookie"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF sanitizers ───
    LabelRule {
        matchers: &["strip_crlf", "escape_header", "sanitize_header"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Open redirect sinks ───
    //
    // Flask `redirect(url)`, Django `HttpResponseRedirect(url)`, FastAPI /
    // Starlette `RedirectResponse(url=...)`.  Tainted URL flowing to any of
    // these without an allowlist check is an open-redirect vector.
    LabelRule {
        matchers: &[
            "redirect",
            "flask.redirect",
            "django.shortcuts.redirect",
            "HttpResponseRedirect",
            "RedirectResponse",
        ],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["validate_redirect_url", "is_safe_redirect", "strip_scheme"],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    // ─── SSTI sinks ───
    //
    // Template-engine constructors / `from_string` factories that accept the
    // template *source string* as arg 0.  `flask.render_template` takes a
    // file PATH (not source) so does NOT match here — the safe API stays
    // clean by name.
    LabelRule {
        matchers: &[
            "=Template",
            "jinja2.Template",
            "jinja2.Environment.from_string",
            "Environment.from_string",
            "mako.template.Template",
            "Template.render",
        ],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: true,
    },
    // ─── XXE sinks ───
    //
    // Python's stock `xml.sax.parseString` / `xml.sax.parse` parsers are
    // XXE-vulnerable by default; `xml.dom.minidom.parseString` /
    // `xml.dom.minidom.parse` likewise resolve external entities through
    // the underlying expat parser unless the entity-loader is hardened.
    // Each entry is the dotted-module suffix; bare `parseString` / `parse`
    // are intentionally avoided to prevent collisions with JSON parsers
    // (`json.loads`), `lxml.etree.fromstring` is excluded — modern lxml
    // disables external entities by default and would over-fire here.
    LabelRule {
        matchers: &[
            "xml.sax.parseString",
            "xml.sax.parse",
            "xml.dom.minidom.parseString",
            "xml.dom.minidom.parse",
            "xml.dom.pulldom.parseString",
            "xml.dom.pulldom.parse",
        ],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
    },
    // `defusedxml.*` is the canonical hardened drop-in: every parser in
    // the package strips external-entity / DTD resolution and raises on
    // the patterns that would otherwise XXE.  Treat any defusedxml
    // call as an XXE sanitizer.
    LabelRule {
        matchers: &[
            "defusedxml.ElementTree.fromstring",
            "defusedxml.ElementTree.parse",
            "defusedxml.minidom.parseString",
            "defusedxml.minidom.parse",
            "defusedxml.sax.parseString",
            "defusedxml.sax.parse",
            "defusedxml.pulldom.parseString",
            "defusedxml.pulldom.parse",
            "defusedxml.lxml.fromstring",
            "defusedxml.lxml.parse",
        ],
        label: DataLabel::Sanitizer(Cap::XXE),
        case_sensitive: true,
    },
];

/// Method-call validators that strip caps from their *receiver* (and
/// any equivalence-class-shaped args) on success, instead of clearing
/// the return value.  Distinct from `RULES`'s `Sanitizer` label, which
/// only clears the return — a poor fit for idioms whose effect is
/// raise-on-failure rather than value-replacement.
///
/// Modeled idioms:
///
/// * `path.relative_to(base)` (pathlib) — raises `ValueError` if `path`
///   is not under `base`.  After a successful return, the receiver is
///   path-contained in `base`.  Strips `Cap::FILE_IO`.  Motivated by
///   CVE-2024-23334 (aiohttp StaticResource symlink-bypass) where the
///   patched code calls `filepath.relative_to(self._directory)` inside
///   a try/except and serves `filepath` afterwards.
pub static RECEIVER_VALIDATORS: &[(&str, Cap)] = &[
    ("relative_to", Cap::FILE_IO),
    (".relative_to", Cap::FILE_IO),
];

pub static GATED_SINKS: &[SinkGate] = &[
    // Legacy single-kwarg gate retained for back-compat: Popen(cmd, shell=True).
    SinkGate {
        callee_matcher: "Popen",
        arg_index: 0,
        dangerous_values: &["True", "true"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: Some("shell"),
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // subprocess.run(cmd, shell=True), multi-kwarg gate using the new
    // presence-aware mechanism.  Payload is arg 1 (after receiver offset
    // applied by the CFG layer when the call is modelled method-style).
    SinkGate {
        callee_matcher: "subprocess.run",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[("shell", &["True", "true"])],
        activation: GateActivation::ValueMatch,
    },
    SinkGate {
        callee_matcher: "subprocess.call",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[("shell", &["True", "true"])],
        activation: GateActivation::ValueMatch,
    },
    SinkGate {
        callee_matcher: "subprocess.Popen",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[("shell", &["True", "true"])],
        activation: GateActivation::ValueMatch,
    },
    // ── Outbound HTTP clients (SSRF + cross-boundary data exfiltration) ───
    //
    // Body-bearing methods (POST / PUT / PATCH / DELETE / request) are
    // gated by destination so that:
    //   * SSRF fires only when taint reaches the URL position (arg 0).
    //   * `DATA_EXFIL` fires only when taint reaches a body kwarg (`data` /
    //     `json` / `files` for requests / aiohttp; `content` / `data` /
    //     `json` / `files` for httpx).
    // The pair lets a single `requests.post(taintedUrl, data=secret)` call
    // report SSRF on the URL flow and DATA_EXFIL on the body flow as
    // independent findings rather than a conflated combined cap.
    //
    // CFG-level kwarg-aware extraction (see `extract_destination_kwarg_pairs`)
    // walks `keyword_argument` siblings and routes matching idents into the
    // gate's `destination_uses` so the SSA sink scan only fires when the
    // body kwarg itself is tainted.
    //
    // The source-sensitivity gate in `ast.rs` strips DATA_EXFIL when the
    // contributing source is `Sensitivity::Plain` (raw `request.args`,
    // `request.form`), so plain user input forwarded to a POST body does
    // not surface — only sensitive sources (cookies, sessions, env, headers)
    // produce a DATA_EXFIL finding.
    SinkGate {
        callee_matcher: "requests.post",
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
        callee_matcher: "requests.post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "requests.put",
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
        callee_matcher: "requests.put",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "requests.patch",
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
        callee_matcher: "requests.patch",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "requests.delete",
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
        callee_matcher: "requests.delete",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json", "files"],
        },
    },
    // requests.request(method, url, ...) — note the URL is at arg 1, not
    // arg 0; method is at arg 0.  Body kwargs at arg 2+ via kwarg expansion.
    SinkGate {
        callee_matcher: "requests.request",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "requests.request",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json", "files"],
        },
    },
    // httpx — `content` is httpx's raw-bytes body kwarg; `data` covers
    // form-encoded; `json` covers JSON-encoded; `files` covers multipart.
    SinkGate {
        callee_matcher: "httpx.post",
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
        callee_matcher: "httpx.post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "httpx.put",
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
        callee_matcher: "httpx.put",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "httpx.patch",
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
        callee_matcher: "httpx.patch",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "httpx.delete",
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
        callee_matcher: "httpx.delete",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    // httpx.request(method, url, ...) — same shape as requests.request.
    SinkGate {
        callee_matcher: "httpx.request",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "httpx.request",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    // Type-qualified variants: `requests.Session()`, `httpx.Client()`,
    // `httpx.AsyncClient()`, `aiohttp.ClientSession()` instances all resolve
    // to the synthetic `HttpClient.<method>` callee text via
    // `resolve_type_qualified_labels`.  Covering both module-level and
    // type-qualified forms ensures `s = requests.Session(); s.post(url, data=x)`
    // and `client = httpx.AsyncClient(); await client.post(url, json=x)` both
    // fire SSRF on the URL and DATA_EXFIL on the body kwarg.
    SinkGate {
        callee_matcher: "HttpClient.post",
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
        callee_matcher: "HttpClient.post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.put",
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
        callee_matcher: "HttpClient.put",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.patch",
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
        callee_matcher: "HttpClient.patch",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.delete",
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
        callee_matcher: "HttpClient.delete",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.request",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.request",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    // aiohttp module-level (`aiohttp.post`, `aiohttp.put`, etc.) — uncommon
    // in real code (idiomatic usage is `async with aiohttp.ClientSession()`),
    // covered for completeness.  ClientSession.<method> dispatches via the
    // type-qualified `HttpClient.<method>` gates above.
    SinkGate {
        callee_matcher: "aiohttp.post",
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
        callee_matcher: "aiohttp.post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json"],
        },
    },
    SinkGate {
        callee_matcher: "aiohttp.put",
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
        callee_matcher: "aiohttp.put",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json"],
        },
    },
    SinkGate {
        callee_matcher: "aiohttp.request",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "aiohttp.request",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json"],
        },
    },
    // Chained-construction variants: `httpx.AsyncClient().post(url, json=x)`
    // / `httpx.Client().post(url, ...)` / `aiohttp.ClientSession().post(...)`.
    // Chain-normalisation strips `()` between dots so the callee text
    // becomes `httpx.AsyncClient.post`; gate matching applies to that
    // normalised form so the chained shape is covered without binding to
    // an intermediate variable.
    SinkGate {
        callee_matcher: "httpx.AsyncClient.post",
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
        callee_matcher: "httpx.AsyncClient.post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "httpx.Client.post",
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
        callee_matcher: "httpx.Client.post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["content", "data", "json", "files"],
        },
    },
    SinkGate {
        callee_matcher: "aiohttp.ClientSession.post",
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
        callee_matcher: "aiohttp.ClientSession.post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json"],
        },
    },
    SinkGate {
        callee_matcher: "requests.Session.post",
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
        callee_matcher: "requests.Session.post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data", "json", "files"],
        },
    },
    // urllib.request.urlopen(req) — when req is a `urllib.request.Request`
    // built with the `data` kwarg, that kwarg becomes the POST body.  The
    // gate fires on `Request(url, data=tainted)` directly: the constructor
    // does not egress, but the convention is that wrapping data in a Request
    // means egress is imminent (the urllib.request.Request → urlopen path).
    // This is a heuristic — the real egress happens at urlopen, but tracking
    // the data flow through the constructor is a fair static approximation.
    SinkGate {
        callee_matcher: "urllib.request.Request",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["data"],
        },
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,

    "return_statement"      => Kind::Return,
    "raise_statement"       => Kind::Throw,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "module"                => Kind::SourceFile,
    "block"                 => Kind::Block,
    "else_clause"           => Kind::Block,
    "elif_clause"           => Kind::Block,
    "with_statement"        => Kind::Block,
    "with_clause"           => Kind::Block,
    "with_item"             => Kind::CallWrapper,
    "function_definition"   => Kind::Function,
    "lambda"                => Kind::Function,
    "try_statement"         => Kind::Try,
    "except_clause"         => Kind::Block,
    "finally_clause"        => Kind::Block,
    "class_definition"      => Kind::Block,
    "decorated_definition"  => Kind::Block,
    "match_statement"       => Kind::Block,
    "case_clause"           => Kind::Block,

    // data-flow
    "call"                  => Kind::CallFn,
    "assignment"            => Kind::Assignment,
    "expression_statement"  => Kind::CallWrapper,

    // trivia
    "comment"               => Kind::Trivia,
    ":"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_statement"      => Kind::Trivia,
    "import_from_statement" => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    // Python parameters: bare identifiers, typed (`x: T`), defaulted
    // (`x=42`), and typed-with-default (`x: T = ...`).  Without the
    // typed forms, type-annotated handlers register zero arity and
    // their parameter taint never participates in summaries.
    param_node_kinds: &[
        "identifier",
        "typed_parameter",
        "default_parameter",
        "typed_default_parameter",
    ],
    self_param_kinds: &[],
    ident_fields: &["name"],
};

/// Framework-conditional rules for Python.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Django) {
        // QuerySet.extra(), raw SQL injection risk.
        // Framework-conditional because `extra` is too generic as a static matcher.
        rules.push(RuntimeLabelRule {
            matchers: vec!["extra".into()],
            label: DataLabel::Sink(Cap::SQL_QUERY),
            case_sensitive: false,
        });
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::KINDS;
    use crate::labels::Kind;

    #[test]
    fn lambda_classified_as_function() {
        assert_eq!(KINDS.get("lambda"), Some(&Kind::Function));
    }

    #[test]
    fn function_definition_classified_as_function() {
        assert_eq!(KINDS.get("function_definition"), Some(&Kind::Function));
    }

    #[test]
    fn lambda_distinct_from_other_kinds() {
        // Ensure lambda doesn't accidentally map to Block or Other
        let kind = KINDS.get("lambda").unwrap();
        assert_ne!(*kind, Kind::Block);
        assert_ne!(*kind, Kind::Other);
    }
}
