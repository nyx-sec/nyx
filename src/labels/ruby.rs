use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["ENV", "gets"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["params"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Rails request object, user-controlled HTTP request data.
    // Dotted matchers work via push_node receiver.method text construction
    // (confirmed by existing Net::HTTP.get matcher in ssrf_net_http fixture).
    LabelRule {
        matchers: &[
            "request.headers",
            "request.body",
            "request.url",
            "request.referrer",
            "request.path",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Sensitive request state: cookies and session stores carry auth material
    // / CSRF tokens / signed user ids the operator did not intend to leak.
    // `infer_source_kind` routes substrings containing "cookie" or "session"
    // through `SourceKind::Cookie` (Sensitive), so flow into outbound request
    // payloads activates the `DATA_EXFIL` cap added below.
    LabelRule {
        matchers: &["request.cookies", "request.session", "cookies", "session"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["CGI.escapeHTML", "ERB::Util.html_escape"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // Rails HTML escaping / sanitization helpers.
    LabelRule {
        matchers: &[
            "CGI.escape",
            "Rack::Utils.escape_html",
            "sanitize",
            "strip_tags",
        ],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "Shellwords.escape",
            "Shellwords.shellescape",
            "Shellwords.join",
            "Shellwords.shelljoin",
            // The `String#shellescape` / `Array#shelljoin` core extensions
            // from `require 'shellwords'`: `src.shellescape`.
            "shellescape",
            "shelljoin",
        ],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // `File.basename` keeps only the final component.
    LabelRule {
        matchers: &["File.basename"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // Type coercion sanitizers
    LabelRule {
        matchers: &["to_i", "to_f"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // ActiveRecord SQL sanitizers
    LabelRule {
        matchers: &["sanitize_sql", "sanitize_sql_array"],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // The adapter's own quoting.  The callee text keeps the `connection`
    // segment of `ActiveRecord::Base.connection.quote(x)`, so these anchor on
    // it and a bare `quote` on an unrelated receiver does not match.
    LabelRule {
        matchers: &[
            "connection.quote",
            "connection.quote_string",
            "connection.quote_table_name",
            "connection.quote_column_name",
            "lease_connection.quote",
            "lease_connection.quote_string",
            "lease_connection.quote_table_name",
            "lease_connection.quote_column_name",
        ],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["URI.encode_www_form_component"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    // `Kernel#system` / `Kernel#exec` are the receiver-less command-execution
    // primitives.  The `=` exact-match sigil restricts these to the bare
    // (no-receiver) form so a same-named method on a typed receiver keeps its
    // own semantics: `conn.exec(sql)` on a `PG::Connection` is a SQL sink, not
    // a shell sink (resolved via the `DatabaseConnection.exec` type-qualified
    // rule below).  Bare `system(cmd)` / `exec(cmd)` still match.  Motivated by
    // CVE-2026-42087 (OpenC3 COSMOS: `@@conn.exec("…'#{start_time}'…")`).
    LabelRule {
        matchers: &["=system", "=exec"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // Bare `Kernel#open(path)` interprets a path beginning with `|` as a
    // shell command (`open("|cmd")` runs `cmd`).  `=open` exact-matcher
    // syntax limits this rule to the bare call, `File.open`, `IO.open`,
    // `URI.open` etc. each have their own non-pipe semantics and are
    // covered by their own labels (or intentionally not labeled as CMDI).
    // CVE-2020-8130 (rake `Rake::FileList#egrep`) was the canonical
    // exploit: an attacker-supplied filename starting with `|` ran through
    // `open(fn, "r")`.  The fix replaced the call with `File.open(fn, "r")`.
    LabelRule {
        matchers: &["=open"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // Backtick shell execution: tree-sitter-ruby represents `` `cmd` `` as a
    // `subshell` node with no callee field. push_node normalises the synthetic
    // callee name to "subshell" and extract_arg_uses lifts interpolation
    // identifiers into positional args, so any tainted `#{var}` participates
    // in sink detection.
    LabelRule {
        matchers: &["subshell"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
    },
    // File I/O sinks: user-controlled paths flowing into File.open/File.new
    // are a path-traversal / arbitrary-read vector.  File.open also participates
    // in the resource-lifecycle acquire/release pair (cfg_analysis::RUBY_RESOURCES),
    // so this entry is additive, it does not disturb resource-leak detection.
    LabelRule {
        matchers: &[
            "File.open",
            "File.new",
            "File.read",
            "IO.read",
            // Phase 13 — write-side and directory-listing path-traversal
            // sinks.  `Pathname.new(p)` is conservative: a Pathname
            // construction with attacker-controlled `p` is the documented
            // entry point for downstream Path / File operations and
            // surfaces the path-traversal vector at the construction
            // site.  `Dir.entries` / `Dir.glob` enumerate filesystem
            // contents, so a tainted path argument is a directory
            // disclosure / glob-injection vector.
            "File.write",
            "IO.write",
            "File.binwrite",
            "IO.binwrite",
            "Pathname.new",
            "Dir.entries",
            "Dir.glob",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["eval"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["puts", "print"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // URI.open is the network-capable Kernel#open wrapper, more specific than
    // plain `open` (excluded to avoid file I/O false positives).
    // OpenURI.open_uri is the canonical low-level URI fetcher that URI.open
    // delegates to — every SSRF-vulnerable Ruby download helper (CarrierWave
    // pre-2.1.1 / 1.3.2, Paperclip, etc.) ultimately reaches it.
    LabelRule {
        matchers: &[
            "Net::HTTP.get",
            "Net::HTTP.post",
            // Phase 14 — `Net::HTTP.start(host, port, ...)` is a session
            // factory whose host argument is the SSRF vector when
            // tainted.  `Net::HTTP.get_response(uri)` is a stdlib
            // convenience wrapper around `start` + `request_get`.
            "Net::HTTP.start",
            "Net::HTTP.get_response",
            "URI.open",
            "OpenURI.open_uri",
            "HTTParty.get",
            "HTTParty.post",
            // Phase 14 — Faraday::Connection verb methods on a typed
            // receiver.  `Faraday.new(url: base)` produces an
            // `HttpClient`-typed value (see `constructor_type`); the
            // `client.get(path)` chain resolves through the
            // type-qualified `HttpClient.get` rule below.  Bare
            // `Faraday.get` / `.post` / etc. are the module-level
            // shorthand the existing `Faraday.post` matcher already
            // covers for DATA_EXFIL; SSRF needs the read-shaped
            // verbs registered explicitly.
            "Faraday.get",
            "Faraday.head",
            "Faraday.delete",
        ],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Type-qualified sinks: resolves when receiver is typed as HttpClient via constructor_type().
    // Handles instance-level calls (client.request) that direct matchers above don't cover.
    LabelRule {
        matchers: &["HttpClient.request", "HttpClient.get", "HttpClient.post"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // ── Cross-boundary data exfiltration ──────────────────────────────────
    //
    // Body-bearing outbound HTTP verb methods.  A flat Sink(DATA_EXFIL) here
    // composes with the SSRF rule above via multi-label classification:
    // `Net::HTTP.post(uri, payload)` reports SSRF on the URL flow (arg 0)
    // and DATA_EXFIL on the body flow (arg 1+) as separate findings.  The
    // source-sensitivity gate in `effective_sink_caps` strips DATA_EXFIL
    // when the contributing source is `Plain` (raw `params`), so this only
    // fires for sensitive sources (cookies / session / env / headers /
    // file / db reads).
    //
    // Covered clients:
    // * `Net::HTTP.post(uri, data, headers)` — stdlib
    // * `Net::HTTP::Post.new(path)` body= setter — emitted as
    //   `Net::HTTP::Post.body=` after Ruby setter normalisation; flat rule
    //   ensures any tainted assignment to `.body` smears into the request
    // * `RestClient.post(url, payload, headers)` — rest-client gem
    // * `Faraday.post(url, body, headers)` — faraday
    // * `HTTParty.post(url, body: ..., headers: ...)` — already a Sink(SSRF)
    //   above, DATA_EXFIL adds independently
    // * `Typhoeus.post(url, body: ...)` — typhoeus
    LabelRule {
        matchers: &[
            "Net::HTTP.post",
            "RestClient.post",
            "RestClient.put",
            "RestClient.patch",
            "Faraday.post",
            "Faraday.put",
            "Faraday.patch",
            "HTTParty.post",
            "HTTParty.put",
            "HTTParty.patch",
            "Typhoeus.post",
            "Typhoeus.put",
            "Typhoeus.patch",
        ],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
    },
    // Generic outbound-method suffix matchers for chained / typed receivers
    // (e.g. `client.post(payload)` where `client` is a configured Faraday or
    // RestClient instance).  Suffix-match keeps the rule compact; source
    // sensitivity gates noise from plain user input.
    LabelRule {
        matchers: &["HttpClient.post", "HttpClient.put", "HttpClient.patch"],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["Marshal.load", "Marshal.restore", "YAML.load"],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
    // Reflection / dynamic class resolution, arbitrary class instantiation from
    // user-controlled names enables gadget chains (similar risk profile to
    // deserialization). Rails adds `constantize`/`safe_constantize` to String.
    LabelRule {
        matchers: &["constantize", "safe_constantize"],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
    // SQL injection: ActiveRecord unsafe raw-query execution APIs.
    // Phase 15 expands coverage with `exec_query` (the raw-SQL execution
    // verb on the ActiveRecord connection adapter) and `select_value` /
    // `select_values` / `select_rows` (driver-level select helpers that
    // accept a literal SQL string).
    LabelRule {
        matchers: &[
            "find_by_sql",
            "connection.execute",
            "lease_connection.execute",
            "select_all",
            "exec_query",
            "select_value",
            "select_values",
            "select_rows",
            "select_one",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Phase 15 — receiver-typed ActiveRecord raw-SQL sinks.  The
    // `ActiveRecordRelation` TypeKind is set by `constructor_type` on
    // class-method scope chains (`User.where(...)` etc.); type-qualified
    // resolution rewrites `relation.find_by_sql(sql)` →
    // `ActiveRecordRelation.find_by_sql` so the chained shape is caught
    // even when the receiver text has lost its model-class prefix.
    LabelRule {
        matchers: &[
            "ActiveRecordRelation.find_by_sql",
            "ActiveRecordRelation.exec_query",
            "ActiveRecordRelation.select_all",
            "ActiveRecordRelation.select_one",
            "ActiveRecordRelation.select_value",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // Raw `pg` gem driver sinks.  `constructor_type` tags
    // `PG::Connection.new(...)` / `PG.connect(...)` receivers as
    // `DatabaseConnection`; the type-qualified resolver rewrites
    // `conn.exec(sql)` → `DatabaseConnection.exec`.  Only the
    // string-interpolating verbs are sinks — `exec_params` /
    // `exec_prepared` / `async_exec_params` use libpq `$1` placeholders and
    // are the documented safe form (CVE-2026-42087's fix swaps `exec` for
    // `exec_params`), so they are intentionally absent.
    LabelRule {
        matchers: &[
            "DatabaseConnection.exec",
            "DatabaseConnection.execute",
            "DatabaseConnection.async_exec",
            "DatabaseConnection.exec_query",
            "DatabaseConnection.query",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // SQL injection: ActiveRecord query methods that accept raw SQL strings.
    // `where` and `order` are the most common Rails SQLi vectors when called
    // with string interpolation (e.g., User.where("name = '#{params[:name]}'")).
    // Broad matchers, verified against fixture fallout.
    LabelRule {
        matchers: &["where", "order", "group", "having", "joins", "pluck"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // Open redirect: redirect_to (Rails) / redirect (Sinatra) with
    // user-controlled destination.  `redirect` is a top-level Sinatra
    // helper; case-sensitive matching keeps it from over-firing on
    // unrelated identifiers.  `redirect_to` is the Rails canonical.
    LabelRule {
        matchers: &["redirect_to"],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["redirect"],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
        case_sensitive: true,
    },
    // Named route helpers (`things_path(page: 1)`) are bare calls that build a
    // host-relative path with escaped segments, so redirecting to one cannot
    // leave the site.  Calls with a receiver or namespace never match.
    // `_url` helpers are excluded: they accept `host:`.  A project function
    // of the same name resolves through its summary first and wins.
    LabelRule {
        matchers: &["~_path"],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &[
            "validate_redirect_url",
            "is_safe_redirect",
            "strip_scheme",
            "ensure_relative_url",
            "assert_relative_path",
            "is_relative_url",
        ],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    // Path traversal: file serving with user-controlled path.
    LabelRule {
        matchers: &["send_file"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    // XSS escape-bypass footguns: html_safe and raw disable auto-escaping.
    LabelRule {
        matchers: &["html_safe", "raw"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // ─── LDAP injection sinks ───
    //
    // `Net::LDAP.new(host:, ...).search(base:, filter:, ...)` is the canonical
    // ruby-ldap shape.  Type-qualified resolution rewrites `ldap.search` →
    // `LdapClient.search` when the receiver was constructed via `Net::LDAP.new`
    // / `Net::LDAP.open` (see [`crate::ssa::type_facts::constructor_type`]).
    // The chained literal form `Net::LDAP.new(...).search(...)` is also caught
    // by the suffix matcher `Net::LDAP.search` after `()` stripping (the
    // post-strip text is `Net::LDAP.new.search`, which ends in `.search`; the
    // explicit `LDAP.search` keyword form `Net::LDAP.search(filter)` matches
    // the same matcher directly).
    LabelRule {
        matchers: &["LdapClient.search", "Net::LDAP.search"],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── LDAP-filter sanitizer ───
    //
    // `Net::LDAP::Filter.escape(value)` applies RFC 4515 escaping; treat any
    // call as clearing the LDAP_INJECTION cap.
    LabelRule {
        matchers: &["Net::LDAP::Filter.escape"],
        label: DataLabel::Sanitizer(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── XPath injection sinks ───
    //
    // `Nokogiri::XML::Node#xpath(expr)`, `at_xpath(expr)`, and `search(expr)`
    // accept the expression string as arg 0; concatenated user input there is
    // the canonical Nokogiri XPath-injection vector.  Suffix matching on the
    // bare method names catches the bound-receiver form (`doc.xpath(expr)`).
    LabelRule {
        matchers: &["xpath", "at_xpath"],
        label: DataLabel::Sink(Cap::XPATH_INJECTION),
        case_sensitive: true,
    },
    // ─── XPath escape sanitizers ───
    //
    // No Nokogiri / stdlib helper escapes XPath metacharacters; project-local
    // `escape_xpath` / `xpath_escape` are the developer-named equivalents.
    LabelRule {
        matchers: &["escape_xpath", "xpath_escape"],
        label: DataLabel::Sanitizer(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF injection sinks ───
    //
    // Rack `Response#set_header(name, value)` / `add_header(name, value)`
    // and `ActionDispatch::Response#headers[]=` write a single header value.
    // The subscript-set form `response.headers["X-Foo"] = bar` is picked up
    // via the LHS-subscript classification path in `cfg/mod.rs`: when the
    // LHS object's member-expression text matches `response.headers` (or a
    // synonym), the assignment is tagged as a HEADER_INJECTION sink.
    // Tainted strings without `\r\n` stripping enable response splitting.
    LabelRule {
        matchers: &["set_header", "add_header"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["response.headers", "res.headers", "self.response.headers"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["strip_crlf", "escape_header", "sanitize_header"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── SSTI sinks ───
    //
    // `ERB.new(template_source)` and `Liquid::Template.parse(source)` accept
    // the template *source string* as arg 0; tainted source there yields
    // arbitrary template execution at the corresponding `result(binding)` /
    // `render` step.  `=ERB.new` exact-matcher syntax limits the rule to the
    // direct call (the leading `=` is the same convention used elsewhere in
    // this file for Kernel-style globals like `=open`).
    LabelRule {
        matchers: &["=ERB.new", "Liquid::Template.parse"],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: true,
    },
    // ─── XXE sinks ───
    //
    // `REXML::Document.new(xml)` instantiates the (legacy, default-vulnerable)
    // pure-Ruby XML parser; an attacker-controlled `xml` is XXE.
    //
    // Nokogiri (`Nokogiri::XML(xml)` / `Nokogiri::XML::Document.parse(xml)`)
    // is XXE-safe by default since 1.10, but resolving external entities
    // requires explicitly opting in via `Nokogiri::XML::ParseOptions::NOENT`
    // (or `DTDLOAD` / `DTDATTR`).  Option-flagged detection lives in
    // `GATED_SINKS` below.
    LabelRule {
        matchers: &["REXML::Document.new"],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
    },
];

/// Ruby gated sinks.  Argument-role-aware classification for callees that
/// are XXE-safe by default but become unsafe when the caller passes an
/// option flag that re-enables external-entity resolution.
///
/// Activation uses the bare-leaf comparison: scope-qualified constants like
/// `Nokogiri::XML::ParseOptions::NOENT` are reduced to the rightmost
/// `name` segment by the `scope_resolution` branch in
/// `cfg::literals::extract_const_macro_arg`, so the
/// `dangerous_values` list stays identifier-bare.
///
/// Default-arg semantics: Ruby `Nokogiri::XML(xml)` with no options arg
/// reaches the gate's `None` activation branch (the activation arg
/// position simply doesn't exist), which falls through to a conservative
/// fire.  Callers wishing to suppress the gate explicitly should pass a
/// safe options literal at the activation position (e.g.
/// `Nokogiri::XML::ParseOptions::DEFAULT_XML`); any non-dangerous
/// scope-qualified constant disables the gate.
pub static GATED_SINKS: &[SinkGate] = &[
    // `Faraday.new(url: tainted)` — base-URL kwarg controls the destination
    // origin for every subsequent verb call on the returned client
    // (`client.get(path)` / `.post` / etc.).  When the kwarg value is
    // attacker-controlled, the constructor itself is the SSRF entry point;
    // the existing type-qualified rules on `HttpClient.get` / `.post` only
    // cover taint flowing into the per-call `path` arg.
    //
    // Activation is `Destination` on positional position 0 with a single
    // `url` field; tree-sitter-ruby emits the kwarg as a `pair` node sibling
    // of the positional args, and `extract_destination_kwarg_pairs` walks
    // those pairs (Ruby support added alongside this gate in
    // `cfg::literals::extract_destination_kwarg_pairs`).
    SinkGate {
        callee_matcher: "Faraday.new",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &["url"],
        },
    },
    // `Nokogiri::XML(xml, url=nil, encoding=nil, options=NIL)` — top-level
    // module method.  arg 3 carries the parse-option flag literal.
    //
    // tree-sitter-ruby parses `Nokogiri::XML(args)` as a `call` whose
    // `receiver` field is the `Nokogiri` constant and `method` field is
    // the `XML` constant (with `::` as the call operator).  `push_node`'s
    // `CallMethod` path joins these as `{receiver}.{method}` → matchable
    // suffix `Nokogiri.XML`.
    SinkGate {
        callee_matcher: "Nokogiri.XML",
        arg_index: 3,
        dangerous_values: &["NOENT", "DTDLOAD", "DTDATTR"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // `Nokogiri::XML::Document.parse(xml, url=nil, encoding=nil, options=NIL)`
    // — receiver is the scope_resolution `Nokogiri::XML::Document` (text of
    // the whole receiver is preserved verbatim) and method is `parse`, so
    // the constructed callee text is `Nokogiri::XML::Document.parse`.
    SinkGate {
        callee_matcher: "Nokogiri::XML::Document.parse",
        arg_index: 3,
        dangerous_values: &["NOENT", "DTDLOAD", "DTDATTR"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // `Nokogiri::HTML(html, ..., options)` shares the same option flags as
    // the XML helper.  Same callee normalization as `Nokogiri.XML`.
    SinkGate {
        callee_matcher: "Nokogiri.HTML",
        arg_index: 3,
        dangerous_values: &["NOENT", "DTDLOAD", "DTDATTR"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // ── File-writing path positions ──────────────────────────────────────
    //
    // `File.write(path, data, mode: 'a')` and friends: only the path is a
    // traversal vector.  The data and the options hash are not.
    SinkGate::payload_positions("File.write", DataLabel::Sink(Cap::FILE_IO), false, &[0]),
    SinkGate::payload_positions("IO.write", DataLabel::Sink(Cap::FILE_IO), false, &[0]),
    SinkGate::payload_positions("File.binwrite", DataLabel::Sink(Cap::FILE_IO), false, &[0]),
    SinkGate::payload_positions("IO.binwrite", DataLabel::Sink(Cap::FILE_IO), false, &[0]),
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if"                    => Kind::If,
    "unless"                => Kind::If,
    "while"                 => Kind::While,
    "until"                 => Kind::While,
    "for"                   => Kind::For,

    "return"                => Kind::Return,
    "break"                 => Kind::Break,
    "next"                  => Kind::Continue,

    // structure
    "program"               => Kind::SourceFile,
    "body_statement"        => Kind::Block,
    // Brace blocks (`{ ... }`, including `->(){ ... }` lambda bodies) expose
    // their body as a `block_body` node (do-end blocks use `body_statement`,
    // already mapped above).  Without this, multi-statement brace-block bodies
    // collapse into a single leaf Seq node and lose all intra-body taint flow.
    "block_body"            => Kind::Block,
    "do_block"              => Kind::Function,
    "then"                  => Kind::Block,
    "else"                  => Kind::Block,
    "elsif"                 => Kind::If,

    // begin/rescue/ensure: handled by build_begin_rescue() in cfg.rs
    "begin"                 => Kind::Try,
    "rescue"                => Kind::Block,
    "ensure"                => Kind::Block,
    // `case`/`when`/`else` lowers through `build_switch`; `case ... in`
    // pattern matching is a separate `case_match` node.
    "case"                  => Kind::Switch,
    "when"                  => Kind::Block,
    "class"                 => Kind::Block,
    "module"                => Kind::Block,
    "do"                    => Kind::Block,
    "block"                 => Kind::Function,

    // data-flow
    "call"                  => Kind::CallMethod,
    "assignment"            => Kind::Assignment,
    // Ruby augmented assignment (`x ||= y`, `x += y`, `x <<= y`, …).  Shares
    // the `left`/`right` fields with `assignment`; modelling it as an
    // Assignment makes the LHS depend on the RHS for taint/type purposes.
    // `x op= y` reads both `x` and `y`, so `def_use` also lists the target
    // as a use (see `cfg::rmw_assignment`).  Covers the memoised-
    // connection idiom `@@conn ||= PG::Connection.new(...)` (CVE-2026-42087).
    "operator_assignment"   => Kind::Assignment,
    "method"                => Kind::Function,
    "singleton_method"      => Kind::Function,
    // Backtick shell execution: treat as a synthetic call so push_node
    // classifies it as a sink and extract_arg_uses lifts interpolation
    // identifiers into positional args.
    "subshell"              => Kind::CallFn,

    // trivia
    "comment"               => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "\n" => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    // `optional_parameter` is `a = 1` and `keyword_parameter` is `a:` / `a: 1`.
    // Splat (`*a`, `**o`) and block (`&b`) parameters are not counted: they
    // bind a variable number of arguments or a block, so no single call-site
    // argument maps to them.
    param_node_kinds: &["identifier", "optional_parameter", "keyword_parameter"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};

/// ActiveRecord query methods that the static [`RULES`] table classifies as
/// `Sink(Cap::SQL_QUERY)`.  These are SQL injection vectors only when arg 0
/// is a string with interpolation (`#{x}`) or a non-literal identifier, the
/// hash form (`where(id: x)`) and the parameterised form (`where("a = ?", x)`)
/// are intrinsically safe because Rails escapes the values.
const AR_QUERY_METHOD_NAMES: &[&str] = &["where", "order", "group", "having", "joins", "pluck"];

/// Tree-sitter argument-0 node kinds that mark an ActiveRecord query call as
/// shape-safe.  Hash literals (`pair`, `hash`), symbol literals
/// (`simple_symbol`, `hash_key_symbol`), array literals (`array`), and pure
/// string literals without `#{...}` interpolation are all safe.  Strings WITH
/// interpolation and identifiers / method calls are *not* in this list ,
/// callers must check `has_interpolation` and the kind separately.
const AR_QUERY_SAFE_ARG0_KINDS: &[&str] = &[
    "pair",
    "hash",
    "simple_symbol",
    "hash_key_symbol",
    "array",
    "string",
    "string_literal",
];

/// Returns `true` when a Ruby `call` node is an ActiveRecord query method
/// (`where`, `order`, `pluck`, …) whose argument 0 has a parameter-safe shape.
///
/// Used by [`crate::cfg`] to synthesise a `Sanitizer(SQL_QUERY)` label on
/// the same node as the `Sink(SQL_QUERY)` label, suppressing both
/// `taint-unsanitised-flow` (sanitiser sees taint at the sink) and
/// `cfg-unguarded-sink` (sanitiser dominates the sink reflexively).
///
/// Real-world FP shapes this closes (redmine, mastodon, diaspora):
/// * `Issue.where(:id => params[:id])`, hash form
/// * `Model.where(id: x, name: y)`, keyword-shorthand pairs
/// * `Project.order(:created_at)`, symbol literal
/// * `Issue.pluck(:id, :name)`, symbol literals
/// * `Model.where("active = ?", x)`, parameterised string
///
/// Real-world TPs preserved:
/// * `User.where("name = '#{name}'")`, string with interpolation
/// * `Model.where(some_string_var)`, dynamic identifier (conservative)
pub fn ar_query_safe_shape(callee_text: &str, arg0_kind: &str, has_interpolation: bool) -> bool {
    // Match the callee's last segment ("Model.where" → "where", "where" → "where").
    let leaf = callee_text.rsplit(['.', ':']).next().unwrap_or(callee_text);
    if !AR_QUERY_METHOD_NAMES.contains(&leaf) {
        return false;
    }
    // Strings are safe only when they don't contain `#{...}` interpolation.
    if matches!(arg0_kind, "string" | "string_literal") && has_interpolation {
        return false;
    }
    AR_QUERY_SAFE_ARG0_KINDS.contains(&arg0_kind)
}

/// Framework-conditional rules for Ruby.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Rails) {
        // Strong parameters, permit/require sanitize user input
        rules.push(RuntimeLabelRule {
            matchers: vec!["permit".into(), "require".into()],
            label: DataLabel::Sanitizer(Cap::all()),
            case_sensitive: false,
        });
    }

    if ctx.has(DetectedFramework::Sinatra) {
        // Sinatra template rendering, user content flows to rendered output
        rules.push(RuntimeLabelRule {
            matchers: vec!["erb".into(), "haml".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    rules
}

#[cfg(test)]
mod ar_query_tests {
    use super::ar_query_safe_shape;

    #[test]
    fn hash_form_is_safe() {
        // Model.where(:id => x) , pair node directly in argument_list
        assert!(ar_query_safe_shape("Model.where", "pair", false));
        // Model.where(id: x)
        assert!(ar_query_safe_shape("where", "pair", false));
    }

    #[test]
    fn symbol_form_is_safe() {
        assert!(ar_query_safe_shape("Project.order", "simple_symbol", false));
        assert!(ar_query_safe_shape("Issue.pluck", "simple_symbol", false));
        assert!(ar_query_safe_shape("Model.joins", "simple_symbol", false));
    }

    #[test]
    fn parameterised_string_is_safe() {
        // Model.where("a = ?", x) , first arg is a string literal w/o interpolation
        assert!(ar_query_safe_shape("where", "string", false));
        assert!(ar_query_safe_shape("where", "string_literal", false));
    }

    #[test]
    fn interpolated_string_is_dangerous() {
        // Model.where("a = #{x}") , string node WITH interpolation child
        assert!(!ar_query_safe_shape("where", "string", true));
    }

    #[test]
    fn dynamic_identifier_is_dangerous() {
        // Model.where(some_var), kind is identifier, not in safe list
        assert!(!ar_query_safe_shape("where", "identifier", false));
    }

    #[test]
    fn array_form_is_safe() {
        // Model.pluck([:id, :name]), uncommon but valid
        assert!(ar_query_safe_shape("pluck", "array", false));
    }

    #[test]
    fn non_ar_method_is_never_suppressed() {
        // find_by_sql is a real raw-SQL sink, never suppress.
        assert!(!ar_query_safe_shape("find_by_sql", "string", false));
        assert!(!ar_query_safe_shape("connection.execute", "pair", false));
    }

    #[test]
    fn callee_with_module_path_resolves_leaf() {
        assert!(ar_query_safe_shape("Foo::Bar.where", "pair", false));
        assert!(ar_query_safe_shape("a.b.c.where", "pair", false));
    }
}

#[cfg(test)]
mod kinds_tests {
    use super::KINDS;
    use crate::labels::Kind;

    #[test]
    fn block_body_is_walkable_block() {
        // Brace blocks (incl. lambda bodies) expose their body as `block_body`;
        // it must be a Block so multi-statement bodies are walked instead of
        // collapsing into one leaf Seq node and losing intra-body taint flow.
        assert_eq!(KINDS.get("block_body"), Some(&Kind::Block));
    }
}

#[cfg(test)]
mod file_write_tests {
    use crate::labels::{Cap, DataLabel, classify_all, classify_gated_sink};

    #[test]
    fn file_write_sinks_check_the_path_only() {
        for callee in ["File.write", "IO.write", "File.binwrite", "IO.binwrite"] {
            assert!(
                classify_all("ruby", callee, None).contains(&DataLabel::Sink(Cap::FILE_IO)),
                "{callee}"
            );
            let gates = classify_gated_sink("ruby", callee, |_| None, |_| None, |_| false);
            let gate = gates
                .iter()
                .find(|g| g.label == DataLabel::Sink(Cap::FILE_IO))
                .unwrap_or_else(|| panic!("{callee} gate"));
            assert_eq!(gate.payload_args, &[0], "{callee}");
        }
    }
}

/// True when a Ruby `system` / `exec` call is a shell-free argv form: two or
/// more command words whose program is a fixed string that is not itself a
/// shell, interpreter or wrapper (`system("git", "log", path)`).  Ruby then
/// execs the program directly, so metacharacters in the later words are inert.
///
/// It is not shell-free when the program is dynamic (`system(cmd, "x")` runs
/// whatever `cmd` names) or when it is `sh`, `bash`, `cmd.exe`, `ruby`, `env`
/// and the like, whose arguments are run as code (`system("sh", "-c", c)`).
/// A leading environment hash, trailing option pairs (`chdir: dir`), a block
/// argument and comments are not command words.  A splat makes the word count
/// unknown, so it is never argv form.
pub fn kernel_exec_is_argv_form(call: tree_sitter::Node, code: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let mut words: Vec<tree_sitter::Node> = Vec::new();
    for (i, child) in args.named_children(&mut cursor).enumerate() {
        match child.kind() {
            "splat_argument" | "hash_splat_argument" => return false,
            "pair" | "block_argument" | "comment" => {}
            "hash" if i == 0 => {}
            _ => words.push(child),
        }
    }
    if words.len() < 2 {
        return false;
    }
    match plain_string_value(words[0], code) {
        Some(program) => !super::is_command_runner_program(&program),
        None => false,
    }
}

/// Value of a Ruby string literal with no interpolation, `None` otherwise.
fn plain_string_value(node: tree_sitter::Node, code: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let mut cursor = node.walk();
    if node
        .named_children(&mut cursor)
        .any(|c| !matches!(c.kind(), "string_content" | "escape_sequence"))
    {
        return None;
    }
    let raw = node.utf8_text(code).ok()?;
    let body = raw.get(1..raw.len().checked_sub(1)?)?;
    Some(body.to_string())
}
