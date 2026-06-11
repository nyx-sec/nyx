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
            "ron::from_str",
            "toml::from_str",
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
        ],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
];

/// Rust gated sinks.  Argument-position-aware classification for callees
/// where activation depends on a literal arg value rather than the bare
/// callee name.
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
];

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
    "match_expression"     => Kind::Block,
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
    use crate::labels::Kind;

    #[test]
    fn mod_item_is_walkable_block_not_trivia() {
        // Inline `mod foo { ... }` must be a Block so the CFG builder recurses
        // into the module body; the old Trivia mapping dropped every function,
        // source, and sink inside inline modules.
        assert_eq!(KINDS.get("mod_item"), Some(&Kind::Block));
        assert_ne!(KINDS.get("mod_item"), Some(&Kind::Trivia));
    }
}
