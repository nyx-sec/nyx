use crate::labels::{Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, SinkGate};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["getenv"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["fgets", "scanf", "fscanf", "gets", "read"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Network input sources
    LabelRule {
        matchers: &["recv", "recvfrom"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    // Generic `sanitize_*` prefix: clears the full cap mask.  A function
    // named `sanitize_*` is a developer-asserted general-purpose
    // sanitizer; without a more specific signal (e.g. an explicit
    // sanitizer label rule with a narrower cap), assume it covers every
    // taint cap that flows through it.  Narrowing to a single cap (e.g.
    // HTML_ESCAPE) under-clears developer-named sanitizers and produces
    // FPs whenever the downstream sink belongs to a different cap (e.g.
    // FMT_STRING via printf), which is the typical case in C/C++ code.
    LabelRule {
        matchers: &["sanitize_"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // Type conversion sanitizers
    LabelRule {
        matchers: &["atoi", "atol", "strtol", "strtoul"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &[
            "system", "popen", "exec", "execl", "execlp", "execle", "execve", "execvp",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["sprintf", "strcpy", "strcat"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["printf", "fprintf"],
        label: DataLabel::Sink(Cap::FMT_STRING),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["fopen", "open"],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["curl_easy_perform"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // ─── LDAP injection sinks ───
    //
    // OpenLDAP / libldap surface: `ldap_search_s(ld, base, scope, filter, ...)`
    // and the asynchronous variant `ldap_search_ext_s(ld, base, scope, filter,
    // attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit, *res)`.
    // The filter argument (position 3) is the LDAP-injection vector.  No
    // standard libldap escape helper exists in the C surface; sanitisation is
    // typically caller-implemented (`sanitize_*` covers the developer-named
    // case via the existing prefix rule above).
    LabelRule {
        matchers: &["ldap_search_s", "ldap_search_ext_s"],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: false,
    },
    // ─── XPath injection sinks ───
    //
    // libxml2 evaluation entry points: `xmlXPathEvalExpression(expr, ctx)`,
    // `xmlXPathEval(expr, ctx)`, `xmlXPathCompile(expr)`.  The expression
    // string is arg 0 and is the canonical XPath-injection vector.
    LabelRule {
        matchers: &["xmlXPathEvalExpression", "xmlXPathEval", "xmlXPathCompile"],
        label: DataLabel::Sink(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
];

/// Gated sinks for C.
///
/// `curl_easy_setopt(handle, option, payload)` is libcurl's option-binding
/// interface; the option identifier at arg 1 selects which slot the payload
/// fills.  `CURLOPT_POSTFIELDS` and `CURLOPT_COPYPOSTFIELDS` carry the
/// request body, while other CURLOPT_* constants designate URL / auth / TLS
/// behaviour and are not DATA_EXFIL-relevant.  Gating on the macro identifier
/// keeps the rule from over-firing on `curl_easy_setopt(h, CURLOPT_URL, url)`
/// (covered separately by the `curl_easy_perform` SSRF flat sink).
///
/// Identifier-based activation is enabled via the macro-arg fallback in
/// `cfg::mod::classify_gated_sink` for `lang == "c"`.  Header-parsing
/// libraries (e.g. libmicrohttpd, mongoose) lack a stable surface and are
/// left to project-specific config.
pub static GATED_SINKS: &[SinkGate] = &[SinkGate {
    callee_matcher: "curl_easy_setopt",
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
    "if_statement"          => Kind::If,
    "while_statement"       => Kind::While,
    "for_statement"         => Kind::For,
    "do_statement"          => Kind::While,
    "switch_statement"      => Kind::Switch,
    "case_statement"        => Kind::Block,
    "labeled_statement"     => Kind::Block,

    "return_statement"      => Kind::Return,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "translation_unit"      => Kind::SourceFile,
    "compound_statement"    => Kind::Block,
    "else_clause"           => Kind::Block,
    "function_definition"   => Kind::Function,

    // data-flow
    "call_expression"       => Kind::CallFn,
    "assignment_expression" => Kind::Assignment,
    "declaration"           => Kind::CallWrapper,
    "expression_statement"  => Kind::CallWrapper,

    // trivia
    "comment"               => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "preproc_include"       => Kind::Trivia,
    "preproc_def"           => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter_declaration"],
    self_param_kinds: &[],
    ident_fields: &["declarator", "name"],
};

/// Benchmark-driven output-parameter source positions for known C APIs.
/// Maps callee name → argument positions that receive Source taint.
pub static OUTPUT_PARAM_SOURCES: &[(&str, &[usize])] = &[
    ("fgets", &[0]),    // fgets(buf, size, stream), buf receives input
    ("gets", &[0]),     // gets(buf), buf receives input
    ("recv", &[1]),     // recv(fd, buf, len, flags)
    ("recvfrom", &[1]), // recvfrom(fd, buf, len, flags, ...)
];

/// Arg-to-arg taint propagation for known C functions.
pub static ARG_PROPAGATIONS: &[super::ArgPropagation] = &[
    super::ArgPropagation {
        callee: "inet_pton",
        from_args: &[1],
        to_args: &[2],
    },
    super::ArgPropagation {
        callee: "inet_aton",
        from_args: &[0],
        to_args: &[1],
    },
];
