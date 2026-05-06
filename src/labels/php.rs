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
    // (response splitting); the same callee is also gated for
    // open-redirect detection on `Location: ...` forms.
    LabelRule {
        matchers: &["=header"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF sanitizers ───
    LabelRule {
        matchers: &["strip_crlf", "escape_header", "sanitize_header"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
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
pub static GATED_SINKS: &[SinkGate] = &[SinkGate {
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
}];

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
