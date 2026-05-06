use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    // Note: PHP `$` prefix is stripped by collect_idents, so match without `$`.
    LabelRule {
        matchers: &[
            "$_GET",
            "_GET",
            "$_POST",
            "_POST",
            "$_REQUEST",
            "_REQUEST",
            "$_COOKIE",
            "_COOKIE",
            "$_FILES",
            "_FILES",
            "$_SERVER",
            "_SERVER",
            "$_ENV",
            "_ENV",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["file_get_contents", "fread"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["htmlspecialchars", "htmlentities"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["escapeshellarg", "escapeshellcmd"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["basename", "realpath"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // PDO parameterized queries
    LabelRule {
        matchers: &["prepare", "bindParam", "bindValue"],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Type-check sanitizers
    LabelRule {
        matchers: &["intval", "floatval", "ctype_digit", "ctype_alpha"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // PHP input filtering
    LabelRule {
        matchers: &["filter_input", "filter_var"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["urlencode", "rawurlencode"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &[
            "system",
            "exec",
            "passthru",
            "shell_exec",
            "proc_open",
            "popen",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["eval", "assert"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["include", "include_once", "require", "require_once"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["unserialize"],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["move_uploaded_file", "copy", "file_put_contents", "fwrite"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["echo", "print"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["mysqli_query", "pg_query", "pg_execute", "query"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // PDO and MySQLi OOP: exec/prepare+execute patterns.
    LabelRule {
        matchers: &[
            "pdo.exec",
            "pdo.query",
            "mysqli.real_query",
            "mysqli_real_query",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Laravel Eloquent: raw SQL methods.
    // DB::raw() → scoped_call_expression, callee text "DB.raw".
    // whereRaw/selectRaw/orderByRaw/havingRaw → member_call_expression on query builder.
    LabelRule {
        matchers: &["DB.raw", "whereRaw", "selectRaw", "orderByRaw", "havingRaw"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // NOTE: `file_get_contents` and `fopen` can fetch URLs (SSRF vector) and
    // local files (LFI vector — `file://` scheme).  As a Sink(SSRF) they only
    // fire when the argument is tainted.  `fopen` is the canonical low-level
    // stream-opening API used by media-import / OEmbed / podcast pipelines
    // (CVE-2026-33486 in roadiz/documents wraps `fopen($url, 'r')` in a
    // public `DownloadedFile::fromUrl` static method that any authenticated
    // backend caller can drive with attacker-controlled URLs).
    LabelRule {
        matchers: &["file_get_contents", "curl_exec", "fopen"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // ── Cross-boundary data exfiltration ──────────────────────────────────
    //
    // Body-bearing outbound HTTP verb methods on the major PHP HTTP clients.
    // Flat sinks here compose with the SSRF rule on `curl_exec` /
    // `file_get_contents` via multi-label classification.  The
    // source-sensitivity gate in `effective_sink_caps` strips DATA_EXFIL
    // when the contributing source is `Plain` (`$_GET`, `$_POST`, `$_REQUEST`),
    // so this only fires for sensitive sources (cookies / sessions /
    // server-side state / env / file / db reads).
    //
    // Covered clients:
    // * `Guzzle\Client::post/put/patch` — guzzlehttp/guzzle
    //   matched by suffix on the verb method (chained `$client->post(...)`).
    // * `Symfony\HttpClient::request` — symfony/http-client
    //   request($method, $url, ['body' => $payload, 'json' => $data, ...])
    // * `Http::post` — Laravel HTTP facade (over Guzzle)
    LabelRule {
        matchers: &[
            "Client.post",
            "Client.put",
            "Client.patch",
            "Client.request",
            "HttpClient.post",
            "HttpClient.put",
            "HttpClient.patch",
            "HttpClient.request",
            "Http.post",
            "Http.put",
            "Http.patch",
        ],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: true,
    },
    // ─── LDAP injection sinks ───
    //
    // PHP's procedural LDAP API: `ldap_search($ds, $base, $filter)`,
    // `ldap_list($ds, $base, $filter)`, `ldap_read($ds, $base, $filter)`.
    // The filter argument is the LDAP-injection vector when concatenated
    // with attacker-controlled input.
    LabelRule {
        matchers: &["ldap_search", "ldap_list", "ldap_read"],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: false,
    },
    // ─── LDAP-filter sanitizer ───
    //
    // `ldap_escape($value, $ignore, LDAP_ESCAPE_FILTER)` applies RFC 4515
    // escaping; treat any `ldap_escape` call as clearing the LDAP_INJECTION
    // cap (the no-flag default also escapes filter metacharacters
    // conservatively).
    LabelRule {
        matchers: &["ldap_escape"],
        label: DataLabel::Sanitizer(Cap::LDAP_INJECTION),
        case_sensitive: false,
    },
    // ─── XPath injection sinks ───
    //
    // `DOMXPath::query($expr, $ctx)` and `DOMXPath::evaluate($expr, $ctx)`
    // accept the expression string as arg 0; concatenated user input there
    // is the canonical PHP XPath-injection vector.  `SimpleXMLElement::xpath`
    // takes the same shape.  Direct flat matchers cover the
    // class-qualified call forms.
    // Type-qualified rewrites: `$xp = new DOMXPath($doc)` tags `$xp` as
    // `TypeKind::XPathClient`, so `$xp->query(...)` / `$xp->evaluate(...)`
    // resolve to `XPathClient.query` / `XPathClient.evaluate`.  Without
    // the distinct TypeKind, bare `query` would match the SQL_QUERY sink.
    LabelRule {
        matchers: &[
            "XPathClient.query",
            "XPathClient.evaluate",
            "DOMXPath::query",
            "DOMXPath::evaluate",
            "SimpleXMLElement::xpath",
        ],
        label: DataLabel::Sink(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // Bare `xpath` method: SimpleXMLElement instances expose `->xpath($expr)`
    // and Symfony / DOMCrawler wrappers do the same.  Suffix matching on
    // `xpath` covers `$xml->xpath(...)` and similar bound-receiver shapes
    // where the receiver type is not statically known.  Case-sensitive to
    // avoid collisions with the `XPath` capitalisation used by qualified
    // names.
    LabelRule {
        matchers: &["xpath"],
        label: DataLabel::Sink(Cap::XPATH_INJECTION),
        case_sensitive: true,
    },
    // ─── XPath escape sanitizers ───
    //
    // No PHP standard library helper escapes XPath metacharacters; project-
    // local `escape_xpath` / `xpath_escape` are the developer-named
    // equivalents.
    LabelRule {
        matchers: &["escape_xpath", "xpath_escape"],
        label: DataLabel::Sanitizer(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF injection sinks ───
    //
    // PHP's `header($line)` writes a raw header line.  Tainted strings
    // without `\r\n` stripping let an attacker inject extra headers
    // (response splitting); see GATED_SINKS for the corresponding
    // OPEN_REDIRECT co-tag on `Location: ...` forms.
    //
    // The HEADER_INJECTION sink is intentionally implemented as a gate
    // (not a flat rule) so the multi-gate SSA dispatch can co-emit it
    // alongside the OPEN_REDIRECT gate on the same call site, producing
    // separate findings for each cap with their canonical rule ids.
    // ─── Header / CRLF sanitizers ───
    LabelRule {
        matchers: &["strip_crlf", "escape_header", "sanitize_header"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Open-redirect URL allowlist sanitizers ───
    //
    // Mirrors the JS/TS rule.  Developer-named functions that allowlist
    // / scheme-strip a redirect URL clear OPEN_REDIRECT taint before it
    // reaches `header("Location: …")`.  PHP also commonly uses
    // `snake_case` variants.
    LabelRule {
        matchers: &[
            "validateRedirectUrl",
            "isSafeRedirect",
            "stripScheme",
            "validate_redirect_url",
            "is_safe_redirect",
            "strip_scheme",
        ],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    // ─── SSTI sinks ───
    //
    // Twig `\Twig\Environment::createTemplate(string $template)` parses an
    // arbitrary template source string at runtime; a tainted source yields
    // SSTI when the resulting template is rendered.  `Environment::render`
    // / `Environment::load` take a *template name* (file lookup, not source)
    // and are intentionally excluded.  After PHP scope-resolution stripping
    // the chain text covers both `$twig->createTemplate($src)` and
    // `Twig\Environment::createTemplate(...)` shapes.
    LabelRule {
        matchers: &["Environment.createTemplate", "Twig.createTemplate"],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: true,
    },
    // ─── XXE sanitizers ───
    //
    // `libxml_disable_entity_loader(true)` (PHP <8) / `libxml_set_external_entity_loader($cb)`
    // disable external-entity expansion process-wide.  Treat their return
    // value as XXE-cleared so config-style fixtures (`libxml_disable_entity_loader(true);
    // simplexml_load_string($xml, ...)`) suppress the gate when the call is
    // present in the same SSA scope.  The flat-rule sanitizer is a coarse
    // approximation, the real config-check pattern would track parser-instance
    // hardening (deferred Layer 2).
    LabelRule {
        matchers: &[
            "libxml_disable_entity_loader",
            "libxml_set_external_entity_loader",
        ],
        label: DataLabel::Sanitizer(Cap::XXE),
        case_sensitive: false,
    },
];

/// Gated sinks for PHP.
///
/// `curl_setopt($ch, CURLOPT_POSTFIELDS, $payload)` is the canonical
/// non-OO PHP HTTP-egress payload binding.  The activation arg (index 1) is
/// a `define`d constant: `CURLOPT_POSTFIELDS` (and the byref-copying variant
/// `CURLOPT_COPYPOSTFIELDS`) carry the request body, while other CURLOPT_*
/// constants designate URL / auth / TLS / behaviour, none of which is
/// DATA_EXFIL-relevant.  Gating on the constant identifier keeps the rule
/// from over-firing on `curl_setopt($ch, CURLOPT_URL, $url)` (covered
/// elsewhere by the `curl_exec` SSRF flat sink).
///
/// Identifier-based activation is enabled via the macro-arg fallback in
/// `cfg::mod::classify_gated_sink` for `lang == "php"`.
pub static GATED_SINKS: &[SinkGate] = &[
    SinkGate {
        callee_matcher: "curl_setopt",
        arg_index: 1,
        dangerous_values: &["CURLOPT_POSTFIELDS", "CURLOPT_COPYPOSTFIELDS"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: true,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // PHP `header($line)` HEADER_INJECTION sink.  Modelled as a gate so
    // it can coexist with the OPEN_REDIRECT gate below: the multi-gate
    // SSA dispatch needs each capability declared on its own gate filter
    // to emit one finding per cap.  Always activates (Destination), with
    // payload arg 0 only (`header()` only accepts the line as arg 0;
    // arg 1 is `replace`/`response_code`, not the line content).
    SinkGate {
        callee_matcher: "=header",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // PHP `simplexml_load_string($xml, $class, $options)` —
    // XXE sink gated on the `LIBXML_NOENT` flag (or `LIBXML_DTDLOAD`,
    // `LIBXML_DTDATTR`).  PHP's libxml is XXE-safe by default since 2.9.0;
    // the gate fires only when the `$options` literal includes one of the
    // dangerous flags.  Identifier-based activation works via the macro-arg
    // fallback in `cfg::mod::classify_gated_sink` for `lang == "php"`.
    SinkGate {
        callee_matcher: "simplexml_load_string",
        arg_index: 2,
        dangerous_values: &["LIBXML_NOENT", "LIBXML_DTDLOAD", "LIBXML_DTDATTR"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    SinkGate {
        callee_matcher: "simplexml_load_file",
        arg_index: 2,
        dangerous_values: &["LIBXML_NOENT", "LIBXML_DTDLOAD", "LIBXML_DTDATTR"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // DOMDocument::loadXML($xml, $options) — same gating as
    // simplexml_load_string.  The chain-normalised callee text for
    // `$dom->loadXML(...)` is `dom.loadXML`; suffix matching on
    // `loadXML` covers the bound-receiver form.
    SinkGate {
        callee_matcher: "loadXML",
        arg_index: 1,
        dangerous_values: &["LIBXML_NOENT", "LIBXML_DTDLOAD", "LIBXML_DTDATTR"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // PHP `header($line)` co-tag for OPEN_REDIRECT.
    //
    // The flat HEADER_INJECTION sink (`=header`) above already fires for
    // any `header(...)` call regardless of the line content.  This gate
    // adds the OPEN_REDIRECT co-tag specifically when the first argument
    // is a `Location: ...` header, so the dashboard / OWASP bucket
    // correctly classifies redirect-class flows independently of CRLF.
    //
    // Activation: arg 0 prefix `Location:` (case-insensitive).  When arg
    // 0 is a constant string starting with `Location:` the gate fires and
    // checks payload arg 0 for taint; constants like `Content-Type: ...`
    // are suppressed by the safe-literal branch.  When arg 0 is a binary
    // expression (`"Location: " . $url`) or otherwise dynamic, the
    // value-extraction returns `None` and the gate fires conservatively
    // — matching the existing convention in `setAttribute`/`parseFromString`.
    SinkGate {
        callee_matcher: "=header",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &["Location:"],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"                  => Kind::If,
    "while_statement"               => Kind::While,
    "for_statement"                 => Kind::For,
    "foreach_statement"             => Kind::For,
    "do_statement"                  => Kind::While,

    "return_statement"              => Kind::Return,
    "throw_expression"              => Kind::Throw,
    "break_statement"               => Kind::Break,
    "continue_statement"            => Kind::Continue,

    // structure
    "program"                       => Kind::SourceFile,
    "compound_statement"            => Kind::Block,
    "else_clause"                   => Kind::Block,
    "else_if_clause"                => Kind::Block,
    "function_definition"           => Kind::Function,
    "method_declaration"            => Kind::Function,
    "switch_statement"              => Kind::Switch,
    "switch_block"                  => Kind::Block,
    "case_statement"                => Kind::Block,
    "default_statement"             => Kind::Block,
    "try_statement"                 => Kind::Try,
    "catch_clause"                  => Kind::Block,
    "finally_clause"                => Kind::Block,
    "colon_block"                   => Kind::Block,
    "anonymous_function_creation_expression" => Kind::Function,
    "arrow_function"                => Kind::Function,
    "class_declaration"             => Kind::Block,
    "declaration_list"              => Kind::Block,
    "interface_declaration"         => Kind::Block,
    "trait_declaration"             => Kind::Block,
    "enum_declaration"              => Kind::Block,
    "enum_declaration_list"         => Kind::Block,

    // data-flow
    "function_call_expression"      => Kind::CallFn,
    "object_creation_expression"    => Kind::CallFn,
    "member_call_expression"        => Kind::CallMethod,
    "scoped_call_expression"        => Kind::CallMethod,
    "assignment_expression"         => Kind::Assignment,
    "expression_statement"          => Kind::CallWrapper,
    "echo_statement"                => Kind::CallWrapper,

    // trivia
    "comment"                       => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "php_tag"                       => Kind::Trivia,
    "namespace_definition"          => Kind::Trivia,
    "namespace_use_declaration"     => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["simple_parameter", "variadic_parameter"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};

/// Framework-conditional rules for PHP.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Laravel) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "Request::input".into(),
                "Request::get".into(),
                "Request::query".into(),
                "Request::post".into(),
                "Request::all".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
    }

    rules
}
