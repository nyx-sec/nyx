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

pub mod header_go;
pub mod header_java;
pub mod header_js;
pub mod header_php;
pub mod header_python;
pub mod header_ruby;
pub mod header_rust;
pub mod go_chi;
pub mod go_echo;
pub mod go_fiber;
pub mod go_gin;
pub mod go_routes;
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
pub mod sqs_java;
pub mod sqs_node;
pub mod sqs_python;
pub mod xpath_java;
pub mod xpath_js;
pub mod xpath_php;
pub mod xpath_python;
pub mod xxe_go;
pub mod xxe_java;
pub mod xxe_php;
pub mod xxe_python;
pub mod xxe_ruby;

pub use header_go::HeaderGoAdapter;
pub use header_java::HeaderJavaAdapter;
pub use header_js::HeaderJsAdapter;
pub use header_php::HeaderPhpAdapter;
pub use header_python::HeaderPythonAdapter;
pub use header_ruby::HeaderRubyAdapter;
pub use header_rust::HeaderRustAdapter;
pub use go_chi::GoChiAdapter;
pub use go_echo::GoEchoAdapter;
pub use go_fiber::GoFiberAdapter;
pub use go_gin::GoGinAdapter;
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
pub use sqs_java::SqsJavaAdapter;
pub use sqs_node::SqsNodeAdapter;
pub use sqs_python::SqsPythonAdapter;
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
    summary
        .callees
        .iter()
        .any(|c| predicate(c.name.as_str()))
}
