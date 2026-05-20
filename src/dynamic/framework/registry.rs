//! Per-language [`super::FrameworkAdapter`] dispatch table.
//!
//! Phase 01 (Track L.0) ships an empty table for every language; the
//! [`super::FrameworkAdapter`] trait, [`super::FrameworkBinding`] data
//! shape, and the [`super::detect_binding`] dispatcher are wired
//! through so subsequent Track-L phases only need to register a
//! concrete adapter here.
//!
//! # Ordering contract
//!
//! Within each `static` slice, adapters must be listed in alphabetical
//! order of [`super::FrameworkAdapter::name`].  The lexical ordering
//! gives a deterministic first-match result that survives merges /
//! rebases without subtle re-ordering bugs.  A `framework` unit test
//! ([`super::tests::registry_is_empty_for_every_lang_phase_01`])
//! captures the Phase-01 starting baseline so a phase that registers
//! its first adapter is forced to update both the slice *and* the
//! regression guard in the same change.

use super::FrameworkAdapter;
use crate::symbol::Lang;

/// Adapters registered for `lang`, returned in deterministic
/// first-match order.  Returns an empty slice for languages that have
/// no adapters registered yet.
pub fn adapters_for(lang: Lang) -> &'static [&'static dyn FrameworkAdapter] {
    match lang {
        Lang::Rust => RUST,
        Lang::C => C,
        Lang::Cpp => CPP,
        Lang::Java => JAVA,
        Lang::Go => GO,
        Lang::Php => PHP,
        Lang::Python => PYTHON,
        Lang::Ruby => RUBY,
        Lang::TypeScript => TYPESCRIPT,
        Lang::JavaScript => JAVASCRIPT,
    }
}

// Phase 03 (Track J.1) registers per-language deserialize-sink
// adapters into the matching language slice.  Phase 04 (Track J.2)
// adds the SSTI-sink adapters.  Within each slice adapters are
// listed in alphabetical order of [`FrameworkAdapter::name`] so a
// later phase that appends a new adapter cannot silently re-order
// the existing first-match.
static RUST: &[&dyn FrameworkAdapter] = &[
    &super::adapters::HeaderRustAdapter,
    &super::adapters::RedirectRustAdapter,
    &super::adapters::RustActixAdapter,
    &super::adapters::RustAxumAdapter,
    &super::adapters::RustRocketAdapter,
    &super::adapters::RustWarpAdapter,
];
static C: &[&dyn FrameworkAdapter] = &[];
static CPP: &[&dyn FrameworkAdapter] = &[];
static JAVA: &[&dyn FrameworkAdapter] = &[
    &super::adapters::HeaderJavaAdapter,
    &super::adapters::JavaDeserializeAdapter,
    &super::adapters::JavaMicronautAdapter,
    &super::adapters::JavaQuarkusAdapter,
    &super::adapters::JavaServletAdapter,
    &super::adapters::JavaSpringAdapter,
    &super::adapters::JavaThymeleafAdapter,
    &super::adapters::LdapSpringAdapter,
    &super::adapters::RedirectJavaAdapter,
    &super::adapters::XpathJavaAdapter,
    &super::adapters::XxeJavaAdapter,
];
static GO: &[&dyn FrameworkAdapter] = &[
    &super::adapters::GoChiAdapter,
    &super::adapters::GoEchoAdapter,
    &super::adapters::GoFiberAdapter,
    &super::adapters::GoGinAdapter,
    &super::adapters::HeaderGoAdapter,
    &super::adapters::RedirectGoAdapter,
    &super::adapters::XxeGoAdapter,
];
static PHP: &[&dyn FrameworkAdapter] = &[
    &super::adapters::HeaderPhpAdapter,
    &super::adapters::LdapPhpAdapter,
    &super::adapters::PhpCodeIgniterAdapter,
    &super::adapters::PhpLaravelAdapter,
    &super::adapters::PhpSymfonyAdapter,
    &super::adapters::PhpTwigAdapter,
    &super::adapters::PhpUnserializeAdapter,
    &super::adapters::RedirectPhpAdapter,
    &super::adapters::XpathPhpAdapter,
    &super::adapters::XxePhpAdapter,
];
static PYTHON: &[&dyn FrameworkAdapter] = &[
    &super::adapters::HeaderPythonAdapter,
    &super::adapters::LdapPythonAdapter,
    &super::adapters::PythonDjangoAdapter,
    &super::adapters::PythonFastApiAdapter,
    &super::adapters::PythonFlaskAdapter,
    &super::adapters::PythonJinja2Adapter,
    &super::adapters::PythonPickleAdapter,
    &super::adapters::PythonStarletteAdapter,
    &super::adapters::RedirectPythonAdapter,
    &super::adapters::XpathPythonAdapter,
    &super::adapters::XxePythonAdapter,
];
static RUBY: &[&dyn FrameworkAdapter] = &[
    &super::adapters::HeaderRubyAdapter,
    &super::adapters::RedirectRubyAdapter,
    &super::adapters::RubyErbAdapter,
    &super::adapters::RubyHanamiAdapter,
    &super::adapters::RubyMarshalAdapter,
    &super::adapters::RubyRailsAdapter,
    &super::adapters::RubySinatraAdapter,
    &super::adapters::XxeRubyAdapter,
];
static TYPESCRIPT: &[&dyn FrameworkAdapter] = &[
    &super::adapters::PpJsonDeepAssignTsAdapter,
    &super::adapters::PpLodashMergeTsAdapter,
    &super::adapters::PpObjectAssignTsAdapter,
    &super::adapters::TsNestAdapter,
];
static JAVASCRIPT: &[&dyn FrameworkAdapter] = &[
    &super::adapters::HeaderJsAdapter,
    &super::adapters::JsExpressAdapter,
    &super::adapters::JsFastifyAdapter,
    &super::adapters::JsHandlebarsAdapter,
    &super::adapters::JsKoaAdapter,
    &super::adapters::JsNestAdapter,
    &super::adapters::PpJsonDeepAssignJsAdapter,
    &super::adapters::PpLodashMergeJsAdapter,
    &super::adapters::PpObjectAssignJsAdapter,
    &super::adapters::RedirectJsAdapter,
    &super::adapters::XpathJsAdapter,
];
