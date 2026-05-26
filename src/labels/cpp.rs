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
        matchers: &["std::cin", "std::getline", "fgets", "scanf", "gets"],
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
    // Type conversion sanitizers (C++ STL forms).
    // The full `std::sto*` family (including 64-bit `*ll`/`*ull` and `*ld`)
    // returns an integral or floating value; downstream string-injection
    // caps no longer apply.
    LabelRule {
        matchers: &[
            "std::stoi",
            "std::stol",
            "std::stoll",
            "std::stoul",
            "std::stoull",
            "std::stof",
            "std::stod",
            "std::stold",
        ],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // Type conversion sanitizers (C-stdlib forms still valid in C++).
    // Numeric parse → caller receives an integral / floating value, not
    // the original string; downstream string-injection caps are cleared.
    LabelRule {
        matchers: &[
            "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull",
        ],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &[
            "system", "popen", "execl", "execlp", "execle", "execve", "execvp",
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
        matchers: &["curl_easy_perform", "connect"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // ─── LDAP injection sinks ───
    //
    // OpenLDAP / libldap C interface (also used from C++ wrappers): the filter
    // argument carries attacker-controlled data unless explicitly escaped.
    LabelRule {
        matchers: &["ldap_search_s", "ldap_search_ext_s"],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: false,
    },
    // ─── XPath injection sinks ───
    //
    // libxml2 (the dominant C++ XML parser surface): `xmlXPathEvalExpression`,
    // `xmlXPathEval`, `xmlXPathCompile` accept the expression string as arg 0.
    LabelRule {
        matchers: &["xmlXPathEvalExpression", "xmlXPathEval", "xmlXPathCompile"],
        label: DataLabel::Sink(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
];

/// Gated sinks for C++.
///
/// Mirror of the C gate set: `curl_easy_setopt` with `CURLOPT_POSTFIELDS` /
/// `CURLOPT_COPYPOSTFIELDS` at arg 1 binds the request body at arg 2.
/// Identifier-based activation is enabled via the macro-arg fallback in
/// `cfg::mod::classify_gated_sink` for `lang == "cpp" / "c++"`.  Modern C++
/// HTTP wrappers (cpr, Boost.Beast) layer over libcurl or directly over the
/// socket; their ergonomic surfaces differ enough that adding gates per-
/// library is left for a follow-up driven by the corpus.
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
    "for_range_loop"        => Kind::For,
    "do_statement"          => Kind::While,
    "switch_statement"      => Kind::Switch,
    "case_statement"        => Kind::Block,
    "labeled_statement"     => Kind::Block,

    "return_statement"      => Kind::Return,
    "throw_statement"       => Kind::Throw,
    "break_statement"       => Kind::Break,
    "continue_statement"    => Kind::Continue,

    // structure
    "translation_unit"      => Kind::SourceFile,
    "compound_statement"    => Kind::Block,
    "else_clause"           => Kind::Block,
    "function_definition"   => Kind::Function,
    "try_statement"         => Kind::Try,
    "catch_clause"          => Kind::Block,
    "lambda_expression"     => Kind::Function,
    // Namespace bodies and C++ class bodies descend as plain Blocks so the
    // CFG builder can reach the nested function_definitions/lambdas inside
    // and extract them as separate bodies.  Without these, a
    // `class_specifier` / `struct_specifier` falls through to the
    // generic `_ =>` arm in `build_sub`, which records a leaf `Seq`
    // node and never walks the body, so inline member-function
    // definitions (and methods of nested classes) are silently dropped.
    "declaration_list"      => Kind::Block,
    "field_declaration_list" => Kind::Block,
    "class_specifier"        => Kind::Block,
    "struct_specifier"       => Kind::Block,
    "union_specifier"        => Kind::Block,
    "enum_specifier"         => Kind::Block,
    "template_declaration"   => Kind::Block,
    "linkage_specification"  => Kind::Block,

    // data-flow
    "call_expression"       => Kind::CallFn,
    "new_expression"        => Kind::CallFn,
    "delete_expression"     => Kind::CallFn,
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
    "using_declaration"     => Kind::Trivia,
    "namespace_definition"  => Kind::Block,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter_declaration"],
    self_param_kinds: &[],
    ident_fields: &["declarator", "name"],
};

/// Benchmark-driven output-parameter source positions for known C++ APIs.
pub static OUTPUT_PARAM_SOURCES: &[(&str, &[usize])] = &[
    ("getline", &[1]), // std::getline(stream, str), str receives input
    ("std::getline", &[1]),
    ("fgets", &[0]),
    ("gets", &[0]),
    ("recv", &[1]),
    ("recvfrom", &[1]),
];

/// Arg-to-arg taint propagation for known C++ functions.
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
