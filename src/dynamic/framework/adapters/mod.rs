//! Concrete [`super::FrameworkAdapter`] implementations.
//!
//! Phase 03 (Track J.1) landed the first four adapters — one per
//! language carrying the `Cap::DESERIALIZE` corpus.  Phase 04 (Track
//! J.2) adds five more, one per template engine carrying the
//! `Cap::SSTI` corpus: Jinja2 (Python), ERB (Ruby), Twig (PHP),
//! Thymeleaf (Java), Handlebars (JavaScript).  Each adapter detects
//! the language's canonical sink inside a function body and stamps a
//! [`super::FrameworkBinding`] with
//! [`crate::evidence::EntryKind::Function`].  Track L.1+ will register
//! the route / framework adapters; the per-cap sink adapters live
//! here so the per-language verticals can ship independently.

pub mod go_chi;
pub mod go_echo;
pub mod go_fiber;
pub mod go_gin;
pub mod go_routes;
pub mod graphql_apollo;
pub mod graphql_gqlgen;
pub mod graphql_graphene;
pub mod graphql_juniper;
pub mod graphql_relay;
pub mod header_go;
pub mod header_java;
pub mod header_js;
pub mod header_php;
pub mod header_python;
pub mod header_ruby;
pub mod header_rust;
pub mod java_deserialize;
pub mod java_micronaut;
pub mod java_quarkus;
pub mod java_routes;
pub mod java_servlet;
pub mod java_spring;
pub mod java_thymeleaf;
pub mod js_express;
pub mod js_fastify;
pub mod js_handlebars;
pub mod js_koa;
pub mod js_nest;
pub mod js_routes;
pub mod kafka_java;
pub mod kafka_python;
pub mod ldap_php;
pub mod ldap_python;
pub mod ldap_spring;
pub mod middleware_django;
pub mod middleware_express;
pub mod middleware_laravel;
pub mod middleware_rails;
pub mod middleware_spring;
pub mod migration_django;
pub mod migration_flask;
pub mod migration_laravel;
pub mod migration_prisma;
pub mod migration_rails;
pub mod migration_sequelize;
pub mod nats_go;
pub mod php_codeigniter;
pub mod php_laravel;
pub mod php_routes;
pub mod php_symfony;
pub mod php_twig;
pub mod php_unserialize;
pub mod pp_json_deep_assign;
pub mod pp_lodash_merge;
pub mod pp_object_assign;
pub mod pubsub_go;
pub mod pubsub_python;
pub mod python_django;
pub mod python_fastapi;
pub mod python_flask;
pub mod python_jinja2;
pub mod python_pickle;
pub mod python_routes;
pub mod python_starlette;
pub mod rabbit_java;
pub mod rabbit_python;
pub mod redirect_go;
pub mod redirect_java;
pub mod redirect_js;
pub mod redirect_php;
pub mod redirect_python;
pub mod redirect_ruby;
pub mod redirect_rust;
pub mod ruby_erb;
pub mod ruby_hanami;
pub mod ruby_marshal;
pub mod ruby_rails;
pub mod ruby_routes;
pub mod ruby_sinatra;
pub mod rust_actix;
pub mod rust_axum;
pub mod rust_rocket;
pub mod rust_routes;
pub mod rust_warp;
pub mod scheduled_celery;
pub mod scheduled_cron;
pub mod scheduled_quartz;
pub mod scheduled_sidekiq;
pub mod sqs_java;
pub mod sqs_node;
pub mod sqs_python;
pub mod websocket_actioncable;
pub mod websocket_channels;
pub mod websocket_socketio;
pub mod websocket_ws;
pub mod xpath_java;
pub mod xpath_js;
pub mod xpath_php;
pub mod xpath_python;
pub mod xxe_go;
pub mod xxe_java;
pub mod xxe_php;
pub mod xxe_python;
pub mod xxe_ruby;

pub use go_chi::GoChiAdapter;
pub use go_echo::GoEchoAdapter;
pub use go_fiber::GoFiberAdapter;
pub use go_gin::GoGinAdapter;
pub use graphql_apollo::GraphqlApolloAdapter;
pub use graphql_gqlgen::GraphqlGqlgenAdapter;
pub use graphql_graphene::GraphqlGrapheneAdapter;
pub use graphql_juniper::GraphqlJuniperAdapter;
pub use graphql_relay::GraphqlRelayAdapter;
pub use header_go::HeaderGoAdapter;
pub use header_java::HeaderJavaAdapter;
pub use header_js::HeaderJsAdapter;
pub use header_php::HeaderPhpAdapter;
pub use header_python::HeaderPythonAdapter;
pub use header_ruby::HeaderRubyAdapter;
pub use header_rust::HeaderRustAdapter;
pub use java_deserialize::JavaDeserializeAdapter;
pub use java_micronaut::JavaMicronautAdapter;
pub use java_quarkus::JavaQuarkusAdapter;
pub use java_servlet::JavaServletAdapter;
pub use java_spring::JavaSpringAdapter;
pub use java_thymeleaf::JavaThymeleafAdapter;
pub use js_express::JsExpressAdapter;
pub use js_fastify::JsFastifyAdapter;
pub use js_handlebars::JsHandlebarsAdapter;
pub use js_koa::JsKoaAdapter;
pub use js_nest::{JsNestAdapter, TsNestAdapter};
pub use kafka_java::KafkaJavaAdapter;
pub use kafka_python::KafkaPythonAdapter;
pub use ldap_php::LdapPhpAdapter;
pub use ldap_python::LdapPythonAdapter;
pub use ldap_spring::LdapSpringAdapter;
pub use middleware_django::MiddlewareDjangoAdapter;
pub use middleware_express::MiddlewareExpressAdapter;
pub use middleware_laravel::MiddlewareLaravelAdapter;
pub use middleware_rails::MiddlewareRailsAdapter;
pub use middleware_spring::MiddlewareSpringAdapter;
pub use migration_django::MigrationDjangoAdapter;
pub use migration_flask::MigrationFlaskAdapter;
pub use migration_laravel::MigrationLaravelAdapter;
pub use migration_prisma::MigrationPrismaAdapter;
pub use migration_rails::MigrationRailsAdapter;
pub use migration_sequelize::MigrationSequelizeAdapter;
pub use nats_go::NatsGoAdapter;
pub use php_codeigniter::PhpCodeIgniterAdapter;
pub use php_laravel::PhpLaravelAdapter;
pub use php_symfony::PhpSymfonyAdapter;
pub use php_twig::PhpTwigAdapter;
pub use php_unserialize::PhpUnserializeAdapter;
pub use pp_json_deep_assign::{PpJsonDeepAssignJsAdapter, PpJsonDeepAssignTsAdapter};
pub use pp_lodash_merge::{PpLodashMergeJsAdapter, PpLodashMergeTsAdapter};
pub use pp_object_assign::{PpObjectAssignJsAdapter, PpObjectAssignTsAdapter};
pub use pubsub_go::PubsubGoAdapter;
pub use pubsub_python::PubsubPythonAdapter;
pub use python_django::PythonDjangoAdapter;
pub use python_fastapi::PythonFastApiAdapter;
pub use python_flask::PythonFlaskAdapter;
pub use python_jinja2::PythonJinja2Adapter;
pub use python_pickle::PythonPickleAdapter;
pub use python_starlette::PythonStarletteAdapter;
pub use rabbit_java::RabbitJavaAdapter;
pub use rabbit_python::RabbitPythonAdapter;
pub use redirect_go::RedirectGoAdapter;
pub use redirect_java::RedirectJavaAdapter;
pub use redirect_js::RedirectJsAdapter;
pub use redirect_php::RedirectPhpAdapter;
pub use redirect_python::RedirectPythonAdapter;
pub use redirect_ruby::RedirectRubyAdapter;
pub use redirect_rust::RedirectRustAdapter;
pub use ruby_erb::RubyErbAdapter;
pub use ruby_hanami::RubyHanamiAdapter;
pub use ruby_marshal::RubyMarshalAdapter;
pub use ruby_rails::RubyRailsAdapter;
pub use ruby_sinatra::RubySinatraAdapter;
pub use rust_actix::RustActixAdapter;
pub use rust_axum::RustAxumAdapter;
pub use rust_rocket::RustRocketAdapter;
pub use rust_warp::RustWarpAdapter;
pub use scheduled_celery::ScheduledCeleryAdapter;
pub use scheduled_cron::ScheduledCronAdapter;
pub use scheduled_quartz::ScheduledQuartzAdapter;
pub use scheduled_sidekiq::ScheduledSidekiqAdapter;
pub use sqs_java::SqsJavaAdapter;
pub use sqs_node::SqsNodeAdapter;
pub use sqs_python::SqsPythonAdapter;
pub use websocket_actioncable::WebsocketActionCableAdapter;
pub use websocket_channels::WebsocketChannelsAdapter;
pub use websocket_socketio::WebsocketSocketIoAdapter;
pub use websocket_ws::WebsocketWsAdapter;
pub use xpath_java::XpathJavaAdapter;
pub use xpath_js::XpathJsAdapter;
pub use xpath_php::XpathPhpAdapter;
pub use xpath_python::XpathPythonAdapter;
pub use xxe_go::XxeGoAdapter;
pub use xxe_java::XxeJavaAdapter;
pub use xxe_php::XxePhpAdapter;
pub use xxe_python::XxePythonAdapter;
pub use xxe_ruby::XxeRubyAdapter;

/// True when any callee in `summary.callees` matches `predicate`.
fn any_callee_matches(
    summary: &crate::summary::FuncSummary,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    summary.callees.iter().any(|c| predicate(c.name.as_str()))
}

/// True when any callee in `summary.callees` matches `name_pred` AND
/// (its receiver matches `receiver_pred` OR its receiver is `None`).
///
/// Used by adapters where the callee name is ambiguous (e.g. Go's bare
/// `Set` / `Add` collides with `url.Values.Set`, Rust's `insert` collides
/// with `BTreeMap::insert`) and the receiver text provides the only
/// non-type-aware discriminator.
///
/// Receivers of `None` fall through to acceptance to preserve backward
/// compatibility with synthetic unit-test summaries built via
/// `CalleeSite::bare(...)` and with adapters whose callees are free
/// functions (no receiver).  Real CFG-derived callees populate
/// `CalleeSite.receiver` whenever the call is a method invocation, so
/// the gate engages on production scans.
fn any_callee_matches_with_receiver(
    summary: &crate::summary::FuncSummary,
    name_pred: impl Fn(&str) -> bool,
    receiver_pred: impl Fn(&str) -> bool,
) -> bool {
    summary.callees.iter().any(|c| {
        if !name_pred(c.name.as_str()) {
            return false;
        }
        match c.receiver.as_deref() {
            Some(r) => receiver_pred(r),
            None => true,
        }
    })
}

/// True when `arg_text` resolves to a function parameter whose 0-based
/// index participates in taint flow — either listed in
/// `summary.tainted_sink_params` (param reaches an internal sink) or
/// `summary.propagating_params` (param flows to the return value).
///
/// Used by the Phase 04 SSTI / Phase 05 XXE / Phase 06 LDAP adapters to
/// reject substring matches in comments by confirming the call's first
/// argument is a real tainted variable rather than a string literal or
/// an unrelated local.
///
/// Per-language sigil stripping covers PHP (`$x`), Ruby (`@x`), and
/// Java/Python/JS (no sigil).  Leading whitespace is also trimmed so
/// adapters can pass the raw `utf8_text` of the argument node.
pub(super) fn arg_is_tainted_param(summary: &crate::summary::FuncSummary, arg_text: &str) -> bool {
    fn strip(s: &str) -> &str {
        s.trim()
            .trim_start_matches('$')
            .trim_start_matches('@')
            .trim_start_matches('&')
    }
    let needle = strip(arg_text);
    let Some(idx) = summary.param_names.iter().position(|p| strip(p) == needle) else {
        return false;
    };
    summary.tainted_sink_params.contains(&idx) || summary.propagating_params.contains(&idx)
}

/// True when any descendant identifier in `node`'s subtree resolves to
/// a function parameter whose 0-based index participates in taint flow
/// (same membership rule as [`arg_is_tainted_param`]).
///
/// Used by Phase 07 XPath adapters where the sink call's expression
/// argument is typically a concat (`"//user[@name='" + name + "'"`)
/// rather than a bare identifier — the walker collects every
/// identifier-shaped leaf and checks each against the summary's
/// tainted-param set.  Pure-literal expressions and concats over
/// unrelated locals fall through.
///
/// `function_scope` is the enclosing function-body subtree.  When a
/// direct identifier in `node` is not itself a tainted param, the
/// walker chases its local assignment within `function_scope` and
/// inspects the RHS for tainted-param references (one hop, enough to
/// cover the common `expr = "..." + name + "..."; eval(expr)` shape
/// without dragging full intra-procedural data flow into the
/// adapter).
pub(super) fn subtree_contains_tainted_param(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    summary: &crate::summary::FuncSummary,
    function_scope: Option<tree_sitter::Node<'_>>,
) -> bool {
    if summary.tainted_sink_params.is_empty() && summary.propagating_params.is_empty() {
        return false;
    }
    let mut hit = false;
    walk_for_param(node, bytes, summary, function_scope, &mut hit);
    hit
}

fn walk_for_param(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    summary: &crate::summary::FuncSummary,
    function_scope: Option<tree_sitter::Node<'_>>,
    hit: &mut bool,
) {
    if *hit {
        return;
    }
    if matches!(
        node.kind(),
        "identifier"
            | "variable_name"
            | "simple_identifier"
            | "name"
            | "type_identifier"
            | "scoped_identifier"
            | "field_identifier"
            | "property_identifier"
    ) && let Ok(text) = node.utf8_text(bytes)
    {
        if arg_is_tainted_param(summary, text) {
            *hit = true;
            return;
        }
        if let Some(scope) = function_scope
            && let Some(rhs) = find_local_assignment_rhs(scope, bytes, text)
        {
            let mut inner = false;
            walk_for_param_no_chase(rhs, bytes, summary, &mut inner);
            if inner {
                *hit = true;
                return;
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_for_param(child, bytes, summary, function_scope, hit);
    }
}

fn walk_for_param_no_chase(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    summary: &crate::summary::FuncSummary,
    hit: &mut bool,
) {
    if *hit {
        return;
    }
    if matches!(
        node.kind(),
        "identifier"
            | "variable_name"
            | "simple_identifier"
            | "name"
            | "type_identifier"
            | "scoped_identifier"
            | "field_identifier"
            | "property_identifier"
    ) && let Ok(text) = node.utf8_text(bytes)
        && arg_is_tainted_param(summary, text)
    {
        *hit = true;
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_for_param_no_chase(child, bytes, summary, hit);
    }
}

fn find_local_assignment_rhs<'a>(
    scope: tree_sitter::Node<'a>,
    bytes: &[u8],
    name: &str,
) -> Option<tree_sitter::Node<'a>> {
    fn strip(s: &str) -> &str {
        s.trim()
            .trim_start_matches('$')
            .trim_start_matches('@')
            .trim_start_matches('&')
    }
    let needle = strip(name);
    let mut hit: Option<tree_sitter::Node<'a>> = None;
    visit(scope, bytes, needle, &mut hit);
    return hit;

    fn visit<'a>(
        node: tree_sitter::Node<'a>,
        bytes: &[u8],
        needle: &str,
        hit: &mut Option<tree_sitter::Node<'a>>,
    ) {
        if hit.is_some() {
            return;
        }
        match node.kind() {
            // Python `expr = rhs` / Ruby `expr = rhs` /
            // JS `expr = rhs` (no `let`).
            "assignment" | "assignment_expression" => {
                let lhs = node
                    .child_by_field_name("left")
                    .or_else(|| node.named_child(0));
                let rhs = node
                    .child_by_field_name("right")
                    .or_else(|| node.named_child(1));
                if let (Some(lhs), Some(rhs)) = (lhs, rhs)
                    && let Ok(text) = lhs.utf8_text(bytes)
                    && strip_sigils(text) == needle
                {
                    *hit = Some(rhs);
                    return;
                }
            }
            // JS `let/const expr = rhs` / TS variant.
            "variable_declarator" => {
                let name_node = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(0));
                let value = node
                    .child_by_field_name("value")
                    .or_else(|| node.named_child(1));
                if let (Some(n), Some(v)) = (name_node, value)
                    && let Ok(text) = n.utf8_text(bytes)
                    && strip_sigils(text) == needle
                {
                    *hit = Some(v);
                    return;
                }
            }
            // Java `Type expr = rhs;`.
            "local_variable_declaration" => {
                let mut cur = node.walk();
                for child in node.named_children(&mut cur) {
                    if child.kind() == "variable_declarator" {
                        let n = child
                            .child_by_field_name("name")
                            .or_else(|| child.named_child(0));
                        let v = child
                            .child_by_field_name("value")
                            .or_else(|| child.named_child(1));
                        if let (Some(n), Some(v)) = (n, v)
                            && let Ok(text) = n.utf8_text(bytes)
                            && strip_sigils(text) == needle
                        {
                            *hit = Some(v);
                            return;
                        }
                    }
                }
            }
            _ => {}
        }
        let mut cur = node.walk();
        for child in node.children(&mut cur) {
            visit(child, bytes, needle, hit);
        }
    }
}

pub(super) fn strip_sigils(s: &str) -> &str {
    s.trim()
        .trim_start_matches('$')
        .trim_start_matches('@')
        .trim_start_matches('&')
}

/// True when the source file visibly mitigates prototype-pollution
/// through a known guard pattern: a quoted `'__proto__'` / `"__proto__"`
/// comparison (canonical per-key filter), or a global
/// `Object.freeze(Object.prototype)` / `Object.seal(Object.prototype)`
/// mitigation. Used by the Phase 10 `pp-lodash-merge` /
/// `pp-object-assign` / `pp-json-deep-assign` adapters to skip binding
/// when the surrounding code already neutralises the gadget.
///
/// The quoted-string form deliberately excludes backtick-wrapped
/// `__proto__` in doc comments so fixtures that mention the key in
/// prose still bind correctly.
pub(super) fn source_filters_proto_keys(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"'__proto__'",
        b"\"__proto__\"",
        b"Object.freeze(Object.prototype",
        b"Object.seal(Object.prototype",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}
