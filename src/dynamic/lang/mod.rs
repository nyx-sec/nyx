//! Per-language harness emitters.
//!
//! Each submodule implements `emit(spec) -> HarnessSource` for one language.
//! The top-level [`emit`] function dispatches on `spec.lang`.

pub mod go;
pub mod java;
pub mod javascript;
pub mod php;
pub mod python;
pub mod rust;

use crate::dynamic::spec::HarnessSpec;
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

/// Dispatch to the appropriate language emitter.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match spec.lang {
        Lang::Python => python::emit(spec),
        Lang::Rust => rust::emit(spec),
        Lang::JavaScript | Lang::TypeScript => javascript::emit(spec),
        Lang::Go => go::emit(spec),
        Lang::Java => java::emit(spec),
        Lang::Php => php::emit(spec),
        _ => Err(UnsupportedReason::LangUnsupported),
    }
}
