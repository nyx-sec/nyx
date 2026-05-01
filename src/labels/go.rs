use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["os.Getenv", "os.LookupEnv", "os.Environ"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "http.Request",
            "r.FormValue",
            "r.URL",
            "r.Body",
            "r.Header",
            "r.Header.Get",
            "r.Header.Values",
            "r.URL.Query",
            "r.URL.Query.Get",
            "r.Cookie",
            "r.Cookies",
            "Request.FormValue",
            "Request.URL",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &[
            "html.EscapeString",
            "template.HTMLEscapeString",
            "template.HTMLEscaper",
        ],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["url.QueryEscape", "url.PathEscape"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["filepath.Clean", "filepath.Base"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // Type conversion sanitizers
    LabelRule {
        matchers: &[
            "strconv.Atoi",
            "strconv.ParseInt",
            "strconv.ParseFloat",
            "strconv.ParseBool",
        ],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["exec.Command"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["db.Query", "db.Exec", "db.QueryRow", "db.Prepare"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // fmt.Printf/Sprintf write to stdout or build strings in memory, not
    // security sinks.  fmt.Fprintf writes to an io.Writer (often http.ResponseWriter)
    // so it IS a security sink for XSS.
    LabelRule {
        matchers: &["fmt.Fprintf"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "os.Open",
            "os.OpenFile",
            "os.Create",
            "ioutil.ReadFile",
            "os.ReadFile",
            // Mutating filesystem operations.  Path-traversal CVEs commonly
            // sink into delete/write rather than read (Owncast CVE-2024-31450
            // sinks into `os.Remove(filepath.Join(root, userInput))`).
            "os.Remove",
            "os.RemoveAll",
            "os.WriteFile",
            "ioutil.WriteFile",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["template.HTML", "template.JS", "template.CSS"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // ── Outbound HTTP clients (SSRF) ───────────────────────────────────
    //
    // These are modeled as destination-aware gated sinks in `GATED_SINKS`
    // below.  Flat Sink rules would over-flag every positional argument as
    // SSRF (so a tainted body in `http.Post(url, contentType, body)` would
    // fire SSRF on the body), and the gate machinery short-circuits when a
    // flat Sink label is already attached to the callee, blocking DATA_EXFIL
    // body-flow gates from running.
    //
    // `net.Dial` / `net.DialTimeout` keep their flat-sink modeling: the
    // first positional arg is the network address with no body / payload
    // companion, so the over-flag concern does not apply.
    LabelRule {
        matchers: &["net.Dial", "net.DialTimeout"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "md5.New",
            "md5.Sum",
            "sha1.New",
            "sha1.Sum",
            "des.NewCipher",
            "rc4.NewCipher",
        ],
        label: DataLabel::Sink(Cap::CRYPTO),
        case_sensitive: false,
    },
];

/// Argument-role-aware Go sinks.  Two classes coexist on the outbound HTTP
/// surface, mirroring the JS/TS modeling:
///
///   * SSRF on the URL-bearing position of a one-shot request (`http.Get`,
///     `http.Post`, `http.NewRequest`, `http.DefaultClient.*`).
///   * `Cap::DATA_EXFIL` on the body / payload position when the source is
///     Sensitive (cookies, headers, env, db reads).  Gates fire only when
///     taint reaches the body argument, so a tainted URL alone never
///     activates DATA_EXFIL and a tainted body alone never activates SSRF.
///
/// `http.NewRequest` / `http.NewRequestWithContext` carry an SSRF gate on
/// their URL position only.  In Go's two-step idiom the actual network
/// call happens at `client.Do(req)`; body taint flows from the body
/// argument through the returned `*http.Request` via default arg → return
/// propagation, and then activates the `http.DefaultClient.Do` DATA_EXFIL
/// gate below.  Modeling NewRequest as a body propagator (rather than a
/// body sink) avoids duplicate findings on the idiomatic
/// `req, _ := http.NewRequest(...); client.Do(req)` shape.
pub static GATED_SINKS: &[SinkGate] = &[
    // ── SSRF gates (URL-bearing position) ────────────────────────────────
    // `http.Get(url)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.Get",
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
    // `http.Head(url)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.Head",
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
    // `http.Post(url, contentType, body)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.Post",
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
    // `http.PostForm(url, data)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.PostForm",
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
    // `http.NewRequest(method, url, body)` — url is arg 1.
    SinkGate {
        callee_matcher: "http.NewRequest",
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
    // `http.NewRequestWithContext(ctx, method, url, body)` — url is arg 2.
    SinkGate {
        callee_matcher: "http.NewRequestWithContext",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.Get(url)` / `.Head(url)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.DefaultClient.Get",
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
        callee_matcher: "http.DefaultClient.Head",
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
    // `http.DefaultClient.Post(url, contentType, body)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.DefaultClient.Post",
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
    // `http.DefaultClient.PostForm(url, data)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.DefaultClient.PostForm",
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
    // ── DATA_EXFIL gates (body-bearing position) ─────────────────────────
    // `http.Post(url, contentType, body)` — body is arg 2.
    SinkGate {
        callee_matcher: "http.Post",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.PostForm(url, data)` — `data` (arg 1) is `url.Values`.  Form
    // bodies serialize the same operator state cookies / headers do, so a
    // tainted Sensitive value reaching the form payload is DATA_EXFIL.
    SinkGate {
        callee_matcher: "http.PostForm",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.Do(req)` — `req` (arg 0) is the `*http.Request`
    // value.  Body taint introduced via either `http.NewRequest(_, _, body)`
    // (default arg → return propagation) or a later `req.Body = body` field
    // write reaches this sink through the request value.
    SinkGate {
        callee_matcher: "http.DefaultClient.Do",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.PostForm(url, data)` — same as `http.PostForm`
    // but invoked through the package-level default `*http.Client`.
    SinkGate {
        callee_matcher: "http.DefaultClient.PostForm",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.Post(url, contentType, body)` — body is arg 2.
    SinkGate {
        callee_matcher: "http.DefaultClient.Post",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // ── Common third-party HTTP clients ─────────────────────────────────
    //
    // `go-resty/resty`: `client.R().SetBody(body).Post(url)` style.
    // `SetBody(body)` carries the body into the chained request; the
    // network call happens at the verb method.  We model the verb
    // methods (Get / Post / Put / Patch / Delete / Send / Execute) as
    // DATA_EXFIL gates with `payload_args: &[]` (empty), which engages
    // the receiver-tainted fallback in `collect_tainted_sink_vars`.  A
    // builder receiver carrying body taint from `SetBody` activates the
    // sink without us needing a positional body arg.
    SinkGate {
        callee_matcher: "resty.Request.Post",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "resty.Request.Put",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "resty.Request.Patch",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `imroc/req`: `req.Post(url, req.BodyJSON(payload))`, the `BodyJSON`
    // / `BodyXML` helpers wrap a tainted payload and pass it as arg 1+ of
    // the verb call.  Since the helper return value carries the body
    // taint, gating the verb on every payload arg is sufficient.
    SinkGate {
        callee_matcher: "req.Post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1, 2, 3],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "req.Put",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1, 2, 3],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"             => Kind::If,
    "for_statement"            => Kind::For,

    "return_statement"         => Kind::Return,
    "break_statement"          => Kind::Break,
    "continue_statement"       => Kind::Continue,

    // structure
    "source_file"              => Kind::SourceFile,
    "block"                    => Kind::Block,
    "statement_list"           => Kind::Block,
    "function_declaration"     => Kind::Function,
    "method_declaration"       => Kind::Function,
    "func_literal"             => Kind::Function,
    "expression_switch_statement"  => Kind::Switch,
    "type_switch_statement"        => Kind::Switch,
    "expression_case"              => Kind::Block,
    "type_case"                    => Kind::Block,
    "default_case"                 => Kind::Block,
    "select_statement"             => Kind::Block,
    "communication_case"           => Kind::Block,
    "go_statement"                 => Kind::Block,
    "defer_statement"              => Kind::Block,

    // data-flow
    "call_expression"          => Kind::CallFn,
    "assignment_statement"     => Kind::Assignment,
    "short_var_declaration"    => Kind::CallWrapper,
    "expression_statement"     => Kind::CallWrapper,
    "var_declaration"          => Kind::CallWrapper,
    "type_assertion_expression" => Kind::Seq,

    // trivia
    "comment"                  => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_declaration"       => Kind::Trivia,
    "package_clause"           => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter_declaration"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};

/// Framework-conditional rules for Go.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Gin) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "c.Param".into(),
                "c.Query".into(),
                "c.PostForm".into(),
                "c.DefaultQuery".into(),
                "c.DefaultPostForm".into(),
                "c.GetHeader".into(),
                "c.Cookie".into(),
                "c.BindJSON".into(),
                "c.ShouldBindJSON".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["c.HTML".into(), "c.String".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    if ctx.has(DetectedFramework::Echo) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "c.QueryParam".into(),
                "c.FormValue".into(),
                "c.Param".into(),
                "c.Bind".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["c.HTML".into(), "c.String".into(), "c.JSON".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    rules
}
