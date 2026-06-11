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
        matchers: &["fgets", "scanf", "fscanf", "sscanf", "gets", "read"],
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
pub static GATED_SINKS: &[SinkGate] = &[
    SinkGate {
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
    },
    // Format-string sinks: only the format parameter is dangerous. Tainted
    // data arguments paired with a literal format string are not format-string
    // vulnerabilities.
    SinkGate {
        callee_matcher: "printf",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FMT_STRING),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // Output sinks: tainted values printed through a literal format string are
    // not format-string vulnerabilities, but they still represent an
    // attacker-controlled output flow in the real-world corpus.
    SinkGate {
        callee_matcher: "printf",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
        payload_args: crate::labels::ALL_ARGS_PAYLOAD,
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "fprintf",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FMT_STRING),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `execv*` forms pass argv as arg 1. The executable path at arg 0 is not
    // shell-parsed, so narrow SHELL_ESCAPE/argv-injection checks to the vector.
    SinkGate {
        callee_matcher: "execv",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "execve",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "execvp",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "execvpe",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
        payload_args: &[1],
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
    ("read", &[1]),     // read(fd, buf, len), buf receives attacker bytes
    // `scanf`/`fscanf`/`sscanf` return a match count; the attacker-controlled
    // bytes land in the variadic output pointers after the format string.
    // OUTPUT_PARAM_SOURCES stores a fixed position list, so we enumerate a
    // conservative span of trailing argument positions to cover the common
    // single- and multi-conversion forms.
    ("scanf", &[1, 2, 3, 4, 5, 6, 7, 8]), // scanf("%s", buf, ...) , outputs start at arg 1
    ("fscanf", &[2, 3, 4, 5, 6, 7, 8]),   // fscanf(stream, "%s", buf, ...) , outputs at arg 2+
    ("sscanf", &[2, 3, 4, 5, 6, 7, 8]),   // sscanf(src, "%s", buf, ...) , outputs at arg 2+
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

#[cfg(test)]
mod tests {
    use crate::labels::output_param_source_positions;

    #[test]
    fn scanf_family_and_read_taint_output_args() {
        // `scanf("%s", buf)` , buf is at arg 1.
        assert_eq!(
            output_param_source_positions("c", "scanf"),
            Some([1usize, 2, 3, 4, 5, 6, 7, 8].as_slice())
        );
        // `fscanf(stream, "%s", buf)` and `sscanf(src, "%s", buf)` , outputs at arg 2+.
        assert_eq!(
            output_param_source_positions("c", "fscanf"),
            Some([2usize, 3, 4, 5, 6, 7, 8].as_slice())
        );
        assert_eq!(
            output_param_source_positions("c", "sscanf"),
            Some([2usize, 3, 4, 5, 6, 7, 8].as_slice())
        );
        // `read(fd, buf, len)` , buf is at arg 1.
        assert_eq!(
            output_param_source_positions("c", "read"),
            Some([1usize].as_slice())
        );
        // Namespaced/qualified callees normalize to the last segment.
        assert_eq!(
            output_param_source_positions("c", "std::sscanf"),
            Some([2usize, 3, 4, 5, 6, 7, 8].as_slice())
        );
    }
}
