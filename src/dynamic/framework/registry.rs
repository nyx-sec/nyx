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

// All slices intentionally empty in Phase 01.  Later Track-L phases
// register concrete adapters (Flask, Spring, axum, Express, …) into
// the appropriate language slice.
static RUST: &[&dyn FrameworkAdapter] = &[];
static C: &[&dyn FrameworkAdapter] = &[];
static CPP: &[&dyn FrameworkAdapter] = &[];
static JAVA: &[&dyn FrameworkAdapter] = &[];
static GO: &[&dyn FrameworkAdapter] = &[];
static PHP: &[&dyn FrameworkAdapter] = &[];
static PYTHON: &[&dyn FrameworkAdapter] = &[];
static RUBY: &[&dyn FrameworkAdapter] = &[];
static TYPESCRIPT: &[&dyn FrameworkAdapter] = &[];
static JAVASCRIPT: &[&dyn FrameworkAdapter] = &[];
