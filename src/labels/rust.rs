use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["std::env::var", "env::var", "source_env"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["source_file"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["fs::read_to_string", "fs::read"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Reads from an open `File`: the bytes land in the buffer passed as the
    // first argument (see `OUTPUT_PARAM_SOURCES`).  Only a receiver typed as a
    // file handle qualifies, so a `Cursor` or `&[u8]` reader over constants
    // stays clean.
    LabelRule {
        matchers: &[
            "FileHandle.read_to_end",
            "FileHandle.read_to_string",
            "FileHandle.read_exact",
            "FileHandle.read",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Inbound HTTP request metadata: headers, cookies, query strings,
    // and body extractors.  These only carry caller-supplied bytes when
    // the framework binds them (the framework-conditional rules attach
    // the same labels for axum / actix / rocket extractors).  Including
    // the bare suffix matchers here means a `req.headers().get("h")`
    // chain in non-framework code (e.g. internal helpers that take an
    // `&HeaderMap`) still surfaces as a Source.  `infer_source_kind`
    // routes these to `Header` / `Cookie` (Sensitive), enabling
    // DATA_EXFIL gating downstream.
    LabelRule {
        matchers: &[
            // Type-qualified (receiver typed as HttpRequest, HeaderMap, ...)
            "HttpRequest.headers",
            "HttpRequest.cookie",
            "HttpRequest.cookies",
            "Request.headers",
            "Request.cookies",
            "Request.uri",
            // Bare HeaderMap / cookie-jar accessors.
            "headers.get",
            "headers.get_all",
            "CookieJar.get",
            "CookieJar.get_private",
            "CookieJar.get_signed",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &["html_escape::encode_safe", "sanitize_", "sanitize_html"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["shell_escape::unix::escape", "sanitize_shell"],
        label: DataLabel::Sanitizer(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // Phase 13 — `Path::canonicalize` (and `tokio::fs::canonicalize`) is
    // the canonical Rust path-traversal sanitiser when paired with a
    // `starts_with(&base)` containment check.  Same convention as the
    // Java / Python `.normalize()` / `.resolve()` sanitiser rules: the
    // call clears the FILE_IO cap on its return so the cap-based gate
    // suppresses the downstream `tokio::fs::*` / `std::fs::*` sink.
    // Bare `canonicalize` would over-fire on unrelated APIs (e.g.
    // `Url::canonicalize`); the qualified forms below are unique to
    // path-handling.
    LabelRule {
        matchers: &[
            "Path.canonicalize",
            "PathBuf.canonicalize",
            "fs::canonicalize",
            "std::fs::canonicalize",
            "tokio::fs::canonicalize",
        ],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &[
            "command::new",
            "std::process::command::new",
            "command::arg",
            "command::args",
            "command::status",
            "command::output",
        ],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["sink_html"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "fs::read_to_string",
            "fs::write",
            "fs::read",
            "fs::remove_file",
            "fs::remove_dir",
            "fs::remove_dir_all",
            "fs::rename",
            "fs::copy",
            "File::open",
            "File::create",
            // Phase 13 — `tokio::fs` async path-traversal sinks.  The
            // suffix matchers also catch the bare `tokio::fs::File::open`
            // chain after paren-strip.  `tokio::fs::*` is the
            // async-runtime-bound mirror of `std::fs::*`; same path
            // arg-0 semantics.
            "tokio::fs::read",
            "tokio::fs::read_to_string",
            "tokio::fs::write",
            "tokio::fs::remove_file",
            "tokio::fs::remove_dir",
            "tokio::fs::remove_dir_all",
            "tokio::fs::rename",
            "tokio::fs::copy",
            "tokio::fs::File::open",
            "tokio::fs::File::create",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "reqwest::get",
            "reqwest::Client.execute",
            "reqwest::Client.get",
            "reqwest::Client.post",
            "reqwest::Client.put",
            "reqwest::Client.delete",
            "reqwest::Client.head",
            "reqwest::Client.patch",
            "reqwest::Client.request",
            // Phase 14 — hyper Client `request(req)` dispatch entry. The
            // `req` builder chain (covered by the type-qualified
            // RequestBuilder.* / Request::builder.* rules below) smears
            // URL taint into the request value via default propagation.
            "hyper::Client.request",
            "hyper::client::Client.request",
            // Chained constructor + verb form: `reqwest::Client::new()
            // .post(url)` reduces (via root-receiver collapse) to chain
            // text `Client::new.post`, so existing `Client.post` matchers
            // miss it.  Cover the chained shape directly.
            "Client::new.get",
            "Client::new.post",
            "Client::new.put",
            "Client::new.delete",
            "Client::new.head",
            "Client::new.patch",
            "Client::new.request",
            // surf free verbs are themselves SSRF gates ,  the URL is
            // their first positional argument.
            "surf::get",
            "surf::post",
            "surf::put",
            "surf::delete",
            "surf::head",
            "surf::patch",
            "surf::connect",
            "surf::trace",
            // ureq free verbs are HTTP request initiators.
            "ureq::get",
            "ureq::post",
            "ureq::put",
            "ureq::delete",
            "ureq::patch",
            "ureq::head",
            // Type-qualified (receiver typed as HttpClient)
            "HttpClient.get",
            "HttpClient.post",
            "HttpClient.put",
            "HttpClient.delete",
            "HttpClient.head",
            "HttpClient.patch",
            "HttpClient.request",
            "HttpClient.execute",
            "HttpClient.send",
        ],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Cross-boundary data exfiltration sinks.  Outbound HTTP egress where
    // a Sensitive source (env, header, cookie, file, db) reaching the
    // request body / payload is a leak distinct from SSRF.  Plain user
    // input is silenced by the source-sensitivity gate, so these only
    // fire when the source carries operator-bound state.
    //
    // Body-binding methods on the request builder: `body`, `json`, `form`,
    // `multipart` (reqwest); `body_string`, `body_json`, `body_bytes`
    // (surf); `send_string`, `send_json`, `send_form` (ureq, which
    // combines body-bind and dispatch).  Plus `.send()` on an HttpClient
    // / RequestBuilder, where the chain receiver is typed.  Chain text
    // matchers like `body.send` cover the all-in-one form
    // `Client::post(url).body(payload).send()`.
    LabelRule {
        matchers: &[
            // Type-qualified terminal verbs (split form, typed receiver).
            "HttpClient.send",
            "HttpClient.execute",
            "RequestBuilder.send",
            // Type-qualified body-bind methods on a typed RequestBuilder.
            "RequestBuilder.body",
            "RequestBuilder.json",
            "RequestBuilder.form",
            "RequestBuilder.multipart",
            "RequestBuilder.body_string",
            "RequestBuilder.body_json",
            "RequestBuilder.body_bytes",
            "RequestBuilder.send_string",
            "RequestBuilder.send_json",
            "RequestBuilder.send_form",
            // surf / ureq method names that are unambiguous in Rust ,
            // they only appear on HTTP request builders, so a bare-name
            // suffix matcher is safe.
            "body_string",
            "body_json",
            "body_bytes",
            "send_string",
            "send_json",
            "send_form",
            // Reqwest chain shapes.  After paren-group strip the chain
            // text becomes `Client::post.body.send`, so the body-bind
            // verb sits before `.send` and a `body.send` suffix matcher
            // pins exfil-only firing to chains that actually bind a body.
            "body.send",
            "json.send",
            "form.send",
            "multipart.send",
            // hyper Request::builder().method(...).body(payload) ,  the
            // body-bind step is the leak point.  `.unwrap` is a common
            // trailing identity method; we cover both shapes.
            "Request::builder.body",
            "Request::builder.method.body",
            "Request::builder.method.body.unwrap",
            "Request::builder.body.unwrap",
            // Two-step reqwest where the user has a dedicated `Client`
            // variable and uses `.execute(req)` on it.
            "Client::new.send",
            "Client::new.execute",
        ],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "rusqlite::Connection.execute",
            "rusqlite::Connection.query",
            "rusqlite::Connection.query_row",
            "rusqlite::Connection.prepare",
            "sqlx::query",
            "sqlx::query_as",
            "sqlx::query_scalar",
            "diesel::sql_query",
            "postgres::Client.execute",
            "postgres::Client.query",
            "postgres::Client.prepare",
            // Type-qualified (receiver typed as DatabaseConnection)
            "DatabaseConnection.execute",
            "DatabaseConnection.query",
            "DatabaseConnection.query_row",
            "DatabaseConnection.prepare",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // `toml::from_str` and `ron::from_str` into a concrete type are left out on
    // purpose: like `serde_json::from_str` they have no polymorphic
    // instantiation surface, and reporting them would flag every config loader.
    // A `dyn` target, as a turbofish (`toml::from_str::<Box<dyn Plugin>>`) or a
    // let annotation (`let p: Box<dyn Plugin> = toml::from_str(s)?`), is
    // attacker-chosen type selection. The label layer recognises the turbofish
    // (`labels::is_polymorphic_decode`) and the CFG builder the annotation
    // (`labels::rust_target_is_dyn`), and both label it like the rule below.
    LabelRule {
        matchers: &[
            "serde_yaml::from_str",
            "serde_yaml::from_slice",
            "serde_yaml::from_reader",
            "bincode::deserialize",
            "bincode::deserialize_from",
            "rmp_serde::from_slice",
            "rmp_serde::from_read",
            "ciborium::from_reader",
        ],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
    // ─── Header / CRLF injection sinks ───
    //
    // `http::HeaderMap::insert(name, val)` / `append(...)` write a single
    // header value.  The canonical idiom is `response.headers_mut().insert(...)`
    // (axum, actix-web `HttpResponse.headers_mut`, hyper `Response::headers_mut`).
    // After paren-group stripping the chain text becomes
    // `response.headers_mut.insert`, so suffix matchers on
    // `headers_mut.insert` / `headers_mut.append` cover the bound-receiver
    // form regardless of the response builder's concrete type.  Tainted
    // strings without CRLF stripping enable response splitting.
    LabelRule {
        matchers: &["headers_mut.insert", "headers_mut.append"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["strip_crlf", "escape_header", "sanitize_header"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Open redirect sinks ───
    //
    // axum / rocket `Redirect::to(url)` / `Redirect::permanent(url)` /
    // `Redirect::temporary(url)` build a 3xx response with the URL in the
    // `Location` header.  Without an allowlist check, a tainted `url` is
    // the canonical Rust open-redirect vector.  Listed unconditionally (not
    // gated on framework detection) so non-framework helpers / re-exports
    // still surface; the framework-conditional rules below are
    // intentionally not duplicating this label.  Actix
    // `HttpResponse::Found().header("Location", x)` is covered by the
    // existing `header` HEADER_INJECTION sink and any Location-line
    // co-tagging is deferred to the abstract-string-domain pattern hook.
    LabelRule {
        matchers: &["Redirect::to", "Redirect::permanent", "Redirect::temporary"],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
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
            // RUSTSEC-2022-0072 (hyper-staticfile open redirect): the fix
            // rebuilds the directory-redirect Location target from the
            // *sanitized* filesystem path returned by `RequestedPath::resolve`
            // (which normalises away traversal and the scheme-relative `//host`
            // prefix) instead of the raw request path. Recognising the sanitiser
            // keeps the patched form silent while the raw-path form still fires.
            "RequestedPath::resolve",
            "RequestedPath.resolve",
        ],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
];

/// Rust gated sinks.  Argument-position-aware classification for callees
/// where activation depends on a literal arg value rather than the bare
/// callee name.
/// Argument positions that receive the bytes of a Source-labelled read
/// (`file.read_to_end(&mut buf)` fills `buf`).  Consulted only when the call
/// already carries a Source label, so a same-named method on another receiver
/// is never treated as a read.
pub static OUTPUT_PARAM_SOURCES: &[(&str, &[usize])] = &[
    ("read_to_end", &[0]),
    ("read_to_string", &[0]),
    ("read_exact", &[0]),
    ("read", &[0]),
];

pub static GATED_SINKS: &[SinkGate] = &[
    // actix-web `HttpResponse::Found().header("Location", url)` (and other
    // builder variants like `Ok().header(...)`, `MovedPermanently().header(...)`).
    // After chain normalisation the callee text is e.g.
    // `HttpResponse.Found.header`; suffix matching on `header` covers every
    // builder variant.
    //
    // Activation: arg 0 case-insensitive equality with `"Location"`.  When
    // arg 0 is a constant string equal to `Location` the gate fires and
    // checks payload arg 1 for taint; constants like `"Content-Type"` are
    // suppressed by the safe-literal branch.  When arg 0 is dynamic the
    // gate fires conservatively (per the existing `setAttribute` /
    // `parseFromString` convention).
    //
    // Mirrors PHP's `=header` Location gate; the Rust analog is split
    // across two args (`name`, `value`) instead of PHP's single `Location: ...`
    // line.
    SinkGate {
        callee_matcher: "header",
        arg_index: 0,
        dangerous_values: &["Location"],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
        case_sensitive: true,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    },
    // ── FILE_IO path-argument confinement ────────────────────────────────
    //
    // The `fs::*` / `File::*` / `tokio::fs::*` calls are flat
    // `Sink(Cap::FILE_IO)` labels (see the sink rule above).  A flat label
    // records no payload position, so the SSA sink scan falls through to the
    // Priority-3 aggregate that checks EVERY used value — receiver plus every
    // positional arg, INCLUDING the implicit-trailing uses SSA lowering
    // appends from the enclosing statement's def-use set.  For a bare
    // `match fs::read(dump.path().join("x.json")) { Ok(v) => .., .. }` that
    // trailing set contains a sibling `file_system`-tainted value (a prior
    // `fs::read` result / a merged phi) that never flows into THIS call's
    // path argument, producing a spurious `file_system -> FILE_IO` self-flow
    // (meilisearch `crates/dump/src/reader/v6/mod.rs:104,126`).
    //
    // These gates carry the SAME `Sink(FILE_IO)` capability as the flat rule
    // (deduped, so no double attribution) and exist ONLY to attach the
    // path-argument position(s) as `payload_args`, confining the sink scan to
    // the file operation's real destination.  `GateActivation::Destination`
    // with `object_destination_fields: &[]` fires unconditionally and treats
    // the whole positional arg at each payload index as the path (mirrors the
    // Go `http.Get` SSRF gates).  Since the gate matcher suffix-matches the
    // same callees as the flat sink rule, it never adds a new sink — it only
    // refines an existing one.  The path is always arg 0; `fs::rename` /
    // `fs::copy` take two path args (from, to).  `fs::write(path, data)`
    // confines to arg 0 only — writing tainted DATA to a fixed path is not a
    // traversal, so arg 1 is intentionally excluded.
    file_io_path_gate("fs::read"),
    file_io_path_gate("fs::read_to_string"),
    file_io_path_gate("fs::write"),
    file_io_path_gate("fs::remove_file"),
    file_io_path_gate("fs::remove_dir_all"),
    file_io_path_gate("fs::remove_dir"),
    file_io_path_gate("File::open"),
    file_io_path_gate("File::create"),
    file_io_path_gate_two("fs::rename"),
    file_io_path_gate_two("fs::copy"),
    // ── SQL text argument confinement ────────────────────────────────────
    //
    // `sqlx::query(sql).bind(v).fetch_all(pool)` is a builder chain: the SQL
    // text is the constructor's arg 0 and every `.bind(v)` value is a bound
    // parameter, which the database never parses as SQL.  The flat
    // `Sink(SQL_QUERY)` label records no payload position, so a tainted
    // `.bind(v)` value (or the pool) was treated as injected SQL.  These gates
    // carry the same capability and confine the sink to arg 0.
    sql_text_gate("sqlx::query"),
    sql_text_gate("sqlx::query_as"),
    sql_text_gate("sqlx::query_scalar"),
    sql_text_gate("diesel::sql_query"),
    // Typed driver connections (`rusqlite`, `postgres`, JDBC-like handles):
    // `conn.execute(sql, params![v])`.  The second argument is the
    // bound-parameter set, never SQL text.
    sql_text_gate("DatabaseConnection.execute"),
    sql_text_gate("DatabaseConnection.query"),
    sql_text_gate("DatabaseConnection.query_row"),
    sql_text_gate("DatabaseConnection.prepare"),
];

/// A `Sink(SQL_QUERY)` gate that confines the sink scan to the SQL text, which
/// is arg 0 of the query constructor.  See the `GATED_SINKS` doc block.
const fn sql_text_gate(matcher: &'static str) -> SinkGate {
    SinkGate {
        label: DataLabel::Sink(Cap::SQL_QUERY),
        ..file_io_path_gate(matcher)
    }
}

/// A `Sink(FILE_IO)` gate that confines the sink scan to the single
/// path-argument position (arg 0).  See the `GATED_SINKS` doc block for the
/// self-flow FP this closes.  `const fn` so it can build the `'static`
/// `GATED_SINKS` slice literal directly.
const fn file_io_path_gate(matcher: &'static str) -> SinkGate {
    SinkGate {
        callee_matcher: matcher,
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    }
}

/// Two-path variant of [`file_io_path_gate`] for `fs::rename(from, to)` /
/// `fs::copy(from, to)`, where both positional args are file paths.
const fn file_io_path_gate_two(matcher: &'static str) -> SinkGate {
    SinkGate {
        payload_args: &[0, 1],
        ..file_io_path_gate(matcher)
    }
}

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_expression"        => Kind::If,
    "loop_expression"      => Kind::InfiniteLoop,
    "while_statement"      => Kind::While,
    "while_expression"     => Kind::While,
    "for_statement"        => Kind::For,
    "for_expression"       => Kind::For,

    "return_statement"     => Kind::Return,
    "return_expression"    => Kind::Return,
    "break_expression"     => Kind::Break,
    "break_statement"      => Kind::Break,
    "continue_expression"  => Kind::Continue,
    "continue_statement"   => Kind::Continue,

    // structure
    "source_file"          => Kind::SourceFile,
    "block"                => Kind::Block,
    "else_clause"          => Kind::Block,
    // `match` lowers through `build_switch`: one dispatch header per arm,
    // arms mutually exclusive, the last arm the exhaustive fallback.
    "match_expression"     => Kind::Switch,
    "match_block"          => Kind::Block,
    "match_arm"            => Kind::Block,
    "unsafe_block"         => Kind::Block,
    "function_item"        => Kind::Function,
    "closure_expression"   => Kind::Function,
    "async_block"          => Kind::Block,
    "impl_item"            => Kind::Block,
    "trait_item"           => Kind::Block,
    "declaration_list"     => Kind::Block,
    // Inline modules `mod foo { ... }` wrap their items in a
    // `declaration_list`; map to Block so the CFG builder recurses into the
    // body and the `function_item`s inside are lowered, instead of dropping
    // the whole module (the old `Kind::Trivia` mapping discarded every
    // function/source/sink inside an inline module).
    "mod_item"             => Kind::Block,

    // data-flow
    "call_expression"        => Kind::CallFn,
    "method_call_expression" => Kind::CallMethod,
    "macro_invocation"       => Kind::CallMacro,
    "let_declaration"        => Kind::CallWrapper,
    "expression_statement"   => Kind::CallWrapper,
    "assignment_expression"  => Kind::Assignment,
    // `x += y`: read-modify-write, see `cfg::rmw_assignment`.
    "compound_assignment_expr" => Kind::Assignment,
    // `x.await` postfix.  Documented per-language so the contract does
    // not depend on the raw-string fallback in `cfg::push_node`; SSA
    // lowering emits `Assign(operand)` for these nodes.
    "await_expression"       => Kind::AwaitForward,

    // struct expressions, recurse so env::var() calls inside field
    // initialisers produce Source-labelled CFG nodes (needed for summaries).
    "struct_expression"       => Kind::Block,
    "field_initializer_list"  => Kind::Block,
    "field_initializer"       => Kind::CallWrapper,

    // trivia
    "line_comment"     => Kind::Trivia,
    "block_comment"    => Kind::Trivia,
    ";" => Kind::Trivia, "," => Kind::Trivia,
    "(" => Kind::Trivia, ")" => Kind::Trivia,
    "{" => Kind::Trivia, "}" => Kind::Trivia, "\n" => Kind::Trivia,
    "use_declaration"  => Kind::Trivia,
    "attribute_item"   => Kind::Trivia,
    "type_item"        => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter"],
    self_param_kinds: &["self_parameter"],
    ident_fields: &["pattern"],
};

/// Framework-conditional rules for Rust.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Axum) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "Path".into(),
                "Query".into(),
                "Json".into(),
                "Form".into(),
                "Multipart".into(),
                "HeaderMap".into(),
                "HeaderMap.get".into(),
                "Request.headers".into(),
                "Request.uri".into(),
                "headers.get".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: true,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["Html".into(), "IntoResponse".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: true,
        });
        // `Redirect::to` is declared unconditionally as Sink(OPEN_REDIRECT)
        // in `RULES` above; no framework-conditional duplicate needed.
    }

    if ctx.has(DetectedFramework::ActixWeb) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "web::Path".into(),
                "web::Query".into(),
                "web::Json".into(),
                "web::Form".into(),
                "web::Bytes".into(),
                "HttpRequest".into(),
                "HttpRequest.headers".into(),
                "HttpRequest.cookie".into(),
                "HttpRequest.match_info".into(),
                "HttpRequest.query_string".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: true,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "HttpResponse.body".into(),
                "HttpResponse.json".into(),
                "HttpResponse.content_type".into(),
                "body".into(),
                "json".into(),
            ],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: true,
        });
    }

    if ctx.has(DetectedFramework::Rocket) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "Json".into(),
                "Form".into(),
                "LenientForm".into(),
                "TempFile".into(),
                "CookieJar".into(),
                "CookieJar.get".into(),
                "CookieJar.get_private".into(),
                "Request.headers".into(),
                "Request.cookies".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: true,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["RawHtml".into(), "content::RawHtml".into(), "Html".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: true,
        });
        // `Redirect::to` is declared unconditionally as Sink(OPEN_REDIRECT)
        // in `RULES` above; no framework-conditional duplicate needed.
    }

    rules
}

/// auth-as-taint label rules for Rust.  Gated by
/// `config.scanner.enable_auth_as_taint`; appended to the runtime rule set
/// when the flag is enabled.  These declare **sinks** (state-changing or
/// outbound operations that should not be reached by an un-checked
/// request-bound id) and **sanitizers** (ownership/membership guards that
/// validate a caller-supplied id).
pub fn phase_c_auth_rules() -> Vec<RuntimeLabelRule> {
    vec![
        // ── Sinks requiring Cap::UNAUTHORIZED_ID ──
        // Realtime / pub-sub: broadcasting on a caller-supplied group/channel
        // id without first verifying membership is the canonical cross-tenant
        // leak.
        RuntimeLabelRule {
            matchers: vec![
                "realtime::publish".into(),
                "realtime::publish_to_group".into(),
                "realtime::publish_to_channel".into(),
                "realtime::broadcast".into(),
                "broadcaster::send".into(),
                "broadcaster::publish".into(),
                "pubsub::publish".into(),
            ],
            label: DataLabel::Sink(Cap::UNAUTHORIZED_ID),
            case_sensitive: false,
        },
        // Database mutations keyed by caller-supplied id.  These overlay the
        // existing SQL_QUERY sink declarations (multi-label composition) so
        // a bare id carrying only UNAUTHORIZED_ID still fires.
        RuntimeLabelRule {
            matchers: vec![
                "rusqlite::Connection.execute".into(),
                "postgres::Client.execute".into(),
                "sqlx::query".into(),
                "sqlx::query_as".into(),
                "diesel::insert_into".into(),
                "diesel::update".into(),
                "diesel::delete".into(),
                // Type-qualified (receiver typed as DatabaseConnection)
                "DatabaseConnection.execute".into(),
                "DatabaseConnection.query".into(),
            ],
            label: DataLabel::Sink(Cap::UNAUTHORIZED_ID),
            case_sensitive: false,
        },
        // Outbound cache writes.
        RuntimeLabelRule {
            matchers: vec![
                "redis::cmd".into(),
                "cache::set".into(),
                "cache::set_ex".into(),
                "cache::insert".into(),
            ],
            label: DataLabel::Sink(Cap::UNAUTHORIZED_ID),
            case_sensitive: false,
        },
        // ── Sanitizers clearing Cap::UNAUTHORIZED_ID ──
        // Ownership and membership guards consumed via call-site
        // argument sanitization (see `is_auth_as_taint_arg_sanitizer`).
        RuntimeLabelRule {
            matchers: vec![
                "check_ownership".into(),
                "has_ownership".into(),
                "require_ownership".into(),
                "ensure_ownership".into(),
                "is_owner".into(),
                "authorize".into(),
                "verify_access".into(),
                "has_permission".into(),
                "can_access".into(),
                "can_manage".into(),
                "require_group_member".into(),
                "require_org_member".into(),
                "require_workspace_member".into(),
                "require_tenant_member".into(),
                "require_team_member".into(),
                "require_membership".into(),
                "check_membership".into(),
                "authz::require".into(),
                "authz::check".into(),
            ],
            label: DataLabel::Sanitizer(Cap::UNAUTHORIZED_ID),
            case_sensitive: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::KINDS;
    use crate::labels::{Cap, DataLabel, Kind, classify_all};

    #[test]
    fn mod_item_is_walkable_block_not_trivia() {
        // Inline `mod foo { ... }` must be a Block so the CFG builder recurses
        // into the module body; the old Trivia mapping dropped every function,
        // source, and sink inside inline modules.
        assert_eq!(KINDS.get("mod_item"), Some(&Kind::Block));
        assert_ne!(KINDS.get("mod_item"), Some(&Kind::Trivia));
    }

    #[test]
    fn typed_text_config_parsers_are_not_deserialize_sinks() {
        let sinks_deser = |callee: &str| {
            classify_all("rust", callee, None)
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::DESERIALIZE)))
        };
        assert!(!sinks_deser("toml::from_str"));
        assert!(!sinks_deser("toml::from_str::<Opt>"));
        assert!(sinks_deser("toml::from_str::<Box<dyn Plugin>>"));
        assert!(sinks_deser("ron::from_str::<Box<dyn Plugin>>"));
        assert!(!sinks_deser("ron::from_str"));
        assert!(!sinks_deser("serde_json::from_str"));
        assert!(sinks_deser("serde_yaml::from_str"));
        assert!(sinks_deser("bincode::deserialize"));
    }

    /// RUSTSEC-2022-0072 (hyper-staticfile): the patched fix routes the
    /// redirect target through `RequestedPath::resolve`, which normalises the
    /// path so it can't become a scheme-relative redirect.  Recognise it as
    /// an OPEN_REDIRECT sanitiser so the patched form stays silent.
    #[test]
    fn requested_path_resolve_is_open_redirect_sanitizer() {
        let labels = classify_all("rust", "RequestedPath::resolve", None);
        assert!(
            labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::OPEN_REDIRECT))),
            "expected RequestedPath::resolve to classify as Sanitizer(OPEN_REDIRECT); got {labels:?}"
        );
    }

    // ── FILE_IO path-argument confinement gates ──────────────────────────
    //
    // The `fs::*` / `File::*` file-IO sinks are also `Source(Cap::all())`, so
    // a `file_system`-tainted value must only reach the sink through its PATH
    // argument, not through a receiver / implicit-trailing SSA use appended
    // from the enclosing statement.  The gate confines the sink scan to the
    // path position(s); see the `GATED_SINKS` doc block.

    fn payload_of(callee: &str) -> Vec<usize> {
        let no_arg = |_: usize| None;
        let no_kw = |_: &str| None;
        let no_kw_present = |_: &str| false;
        let result =
            crate::labels::classify_gated_sink("rust", callee, no_arg, no_kw, no_kw_present);
        let m = result
            .iter()
            .find(|m| m.label == DataLabel::Sink(Cap::FILE_IO))
            .unwrap_or_else(|| panic!("expected FILE_IO gate for {callee}; got {result:?}"));
        m.payload_args.to_vec()
    }

    #[test]
    fn file_io_single_path_gates_confine_to_arg_zero() {
        // Every single-path file operation confines to arg 0.  `fs::write(path,
        // data)` deliberately excludes arg 1 (writing tainted DATA to a fixed
        // path is not a traversal).
        for callee in [
            "fs::read",
            "fs::read_to_string",
            "fs::write",
            "fs::remove_file",
            "fs::remove_dir",
            "fs::remove_dir_all",
            "File::open",
            "File::create",
        ] {
            assert_eq!(payload_of(callee), vec![0], "callee {callee}");
        }
    }

    #[test]
    fn file_io_two_path_gates_confine_to_args_zero_and_one() {
        // `fs::rename(from, to)` / `fs::copy(from, to)` take two path args.
        assert_eq!(payload_of("fs::rename"), vec![0, 1]);
        assert_eq!(payload_of("fs::copy"), vec![0, 1]);
    }

    #[test]
    fn file_io_gate_suffix_matches_tokio_and_std_qualified_forms() {
        // Suffix matching lets one `fs::read` gate cover the `std::fs::read`
        // and `tokio::fs::read` qualified forms (the async mirror), and
        // `File::open` cover `tokio::fs::File::open`.
        assert_eq!(payload_of("std::fs::read"), vec![0]);
        assert_eq!(payload_of("tokio::fs::read"), vec![0]);
        assert_eq!(payload_of("tokio::fs::File::open"), vec![0]);
    }

    #[test]
    fn file_io_gate_does_not_add_sink_for_non_file_callee() {
        // The gate only refines callees already carrying the flat FILE_IO
        // label; an unrelated callee must not gate-match into a FILE_IO sink.
        let no_arg = |_: usize| None;
        let no_kw = |_: &str| None;
        let no_kw_present = |_: &str| false;
        let result = crate::labels::classify_gated_sink(
            "rust",
            "config::read_settings",
            no_arg,
            no_kw,
            no_kw_present,
        );
        assert!(
            !result
                .iter()
                .any(|m| m.label == DataLabel::Sink(Cap::FILE_IO)),
            "config::read_settings must not gate-match a FILE_IO sink; got {result:?}"
        );
    }
}
