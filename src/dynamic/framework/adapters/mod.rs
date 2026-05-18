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

pub mod java_deserialize;
pub mod java_thymeleaf;
pub mod js_handlebars;
pub mod ldap_php;
pub mod ldap_python;
pub mod ldap_spring;
pub mod php_twig;
pub mod php_unserialize;
pub mod python_jinja2;
pub mod python_pickle;
pub mod ruby_erb;
pub mod ruby_marshal;
pub mod xpath_java;
pub mod xpath_js;
pub mod xpath_php;
pub mod xpath_python;
pub mod xxe_go;
pub mod xxe_java;
pub mod xxe_php;
pub mod xxe_python;
pub mod xxe_ruby;

pub use java_deserialize::JavaDeserializeAdapter;
pub use java_thymeleaf::JavaThymeleafAdapter;
pub use js_handlebars::JsHandlebarsAdapter;
pub use ldap_php::LdapPhpAdapter;
pub use ldap_python::LdapPythonAdapter;
pub use ldap_spring::LdapSpringAdapter;
pub use php_twig::PhpTwigAdapter;
pub use php_unserialize::PhpUnserializeAdapter;
pub use python_jinja2::PythonJinja2Adapter;
pub use python_pickle::PythonPickleAdapter;
pub use ruby_erb::RubyErbAdapter;
pub use ruby_marshal::RubyMarshalAdapter;
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
