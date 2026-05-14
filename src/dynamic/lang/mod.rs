//! Per-language harness emitters.
//!
//! Each submodule implements [`LangEmitter`] for one language. The top-level
//! [`emit`] function dispatches on `spec.lang` and validates `spec.entry_kind`
//! against the chosen emitter's [`LangEmitter::entry_kinds_supported`] list
//! before delegating, so unsupported entry kinds short-circuit with a typed
//! `UnsupportedReason::EntryKindUnsupported` rather than producing a
//! never-runnable harness.
//!
//! Two free helpers — [`entry_kinds_supported`] and [`entry_kind_hint`] — wrap
//! the trait dispatch so callers outside the harness build path (notably the
//! verifier, which surfaces an `Inconclusive` verdict with the supported list
//! and hint baked in) can advertise capability without instantiating a spec.

pub mod c;
pub mod cpp;
pub mod go;
pub mod java;
pub mod javascript;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod typescript;

use crate::dynamic::spec::{EntryKind, HarnessSpec};
use crate::evidence::UnsupportedReason;
use crate::symbol::Lang;

/// Generated harness source ready to write to disk.
#[derive(Debug, Clone)]
pub struct HarnessSource {
    /// Harness source code as a UTF-8 string.
    pub source: String,
    /// Filename for the harness (e.g. `"harness.py"`, `"src/main.rs"`).
    pub filename: String,
    /// Shell command to invoke the harness (relative to the workdir).
    pub command: Vec<String>,
    /// Additional files to write to the workdir alongside the main source.
    /// Each entry is `(relative_path, content)`. Subdirectories are created
    /// automatically (e.g. `"Cargo.toml"` or `"src/entry.rs"`).
    pub extra_files: Vec<(String, String)>,
    /// Where to copy the entry source file (relative to workdir).
    /// `None` = workdir root (Python default).
    /// `Some("src/entry.rs")` = Rust module path.
    pub entry_subpath: Option<String>,
}

/// Per-language harness emitter contract.
///
/// Implementations are zero-sized unit structs (one per `src/dynamic/lang/*.rs`
/// module).  The [`emit`](LangEmitter::emit) method is the legacy
/// per-language entry point retained for the build pipeline; the two
/// capability methods are consulted both at dispatch time (`lang::emit`
/// pre-flight check) and by the verifier when constructing
/// `Inconclusive(EntryKindUnsupported { … })`.
pub trait LangEmitter {
    /// Build a harness source bundle for `spec`.
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason>;

    /// The set of [`EntryKind`] variants this emitter understands.
    ///
    /// Must be non-empty: every emitter advertises at least one shape it can
    /// (or will) drive — even stub modules whose `emit` returns
    /// `LangUnsupported`.  Empty would be indistinguishable from "language
    /// not in the dispatch table" and would defeat the structured
    /// advertisement that callers consume.
    fn entry_kinds_supported(&self) -> &'static [EntryKind];

    /// Human-actionable hint produced when `attempted` is not in
    /// [`entry_kinds_supported`](LangEmitter::entry_kinds_supported).
    ///
    /// The string is consumed by
    /// [`crate::evidence::InconclusiveReason::EntryKindUnsupported::hint`] and
    /// surfaces directly to operators triaging dynamic verification gaps;
    /// keep it specific (name the supported kinds, name the phase that will
    /// extend support).
    fn entry_kind_hint(&self, attempted: EntryKind) -> String;
}

/// Dispatch to the appropriate language emitter.
///
/// Validates `spec.entry_kind` against the chosen emitter's supported list
/// before delegating; an unsupported entry kind short-circuits with
/// [`UnsupportedReason::EntryKindUnsupported`] so the verifier can surface a
/// structured `Inconclusive` verdict with the supported list and hint baked
/// in (instead of producing a never-runnable harness).
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    let supported = entry_kinds_supported(spec.lang);
    if !supported.is_empty() && !supported.contains(&spec.entry_kind) {
        return Err(UnsupportedReason::EntryKindUnsupported);
    }
    dispatch(spec.lang, |e| e.emit(spec))
        .unwrap_or(Err(UnsupportedReason::LangUnsupported))
}

/// Public free-fn dispatcher for the supported entry kinds of `lang`.
///
/// Returns an empty slice when `lang` has no registered emitter — callers
/// distinguish that from "emitter exists but advertises none" by treating
/// empty as "language unsupported".
pub fn entry_kinds_supported(lang: Lang) -> &'static [EntryKind] {
    dispatch(lang, |e| e.entry_kinds_supported()).unwrap_or(&[])
}

/// Public free-fn dispatcher for an emitter's hint about `attempted`.
///
/// Falls back to a generic message when `lang` has no registered emitter so
/// callers do not need to special-case that path.
pub fn entry_kind_hint(lang: Lang, attempted: EntryKind) -> String {
    dispatch(lang, |e| e.entry_kind_hint(attempted)).unwrap_or_else(|| {
        format!(
            "no harness emitter is registered for {lang:?}; attempted {attempted}"
        )
    })
}

/// Internal helper: invoke `f` against the emitter registered for `lang`,
/// returning `None` when no emitter is registered for that language.
fn dispatch<R>(lang: Lang, f: impl FnOnce(&dyn LangEmitter) -> R) -> Option<R> {
    let emitter: Option<&dyn LangEmitter> = match lang {
        Lang::Python => Some(&python::PythonEmitter),
        Lang::Rust => Some(&rust::RustEmitter),
        Lang::JavaScript => Some(&javascript::JavaScriptEmitter),
        Lang::TypeScript => Some(&typescript::TypeScriptEmitter),
        Lang::Go => Some(&go::GoEmitter),
        Lang::Java => Some(&java::JavaEmitter),
        Lang::Php => Some(&php::PhpEmitter),
        Lang::Ruby => Some(&ruby::RubyEmitter),
        Lang::C => Some(&c::CEmitter),
        Lang::Cpp => Some(&cpp::CppEmitter),
    };
    emitter.map(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registered emitter must advertise at least one entry kind so the
    /// verifier never produces an empty `supported` list in
    /// `Inconclusive(EntryKindUnsupported { supported, .. })`.
    #[test]
    fn every_lang_advertises_at_least_one_entry_kind() {
        for lang in [
            Lang::Python,
            Lang::Rust,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Go,
            Lang::Java,
            Lang::Php,
            Lang::Ruby,
            Lang::C,
            Lang::Cpp,
        ] {
            let kinds = entry_kinds_supported(lang);
            assert!(
                !kinds.is_empty(),
                "{lang:?} emitter must advertise at least one EntryKind"
            );
        }
    }

    #[test]
    fn entry_kind_hint_mentions_attempted() {
        let hint = entry_kind_hint(Lang::Python, EntryKind::HttpRoute);
        assert!(
            hint.contains("HttpRoute"),
            "hint must mention the attempted entry kind, got: {hint:?}"
        );
    }
}
