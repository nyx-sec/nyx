//! Per-language harness emitters.
//!
//! Each submodule implements `emit(spec) -> HarnessSource` for one language.
//! The top-level [`emit`] function dispatches on `spec.lang`.

pub mod python;

use crate::dynamic::spec::HarnessSpec;
use crate::evidence::UnsupportedReason;
use crate::symbol::Lang;

/// Generated harness source ready to write to disk.
#[derive(Debug, Clone)]
pub struct HarnessSource {
    /// Harness source code as a UTF-8 string.
    pub source: String,
    /// Filename for the harness (e.g. `"harness.py"`).
    pub filename: String,
    /// Shell command to invoke the harness (relative to the workdir).
    pub command: Vec<String>,
}

/// Dispatch to the appropriate language emitter.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match spec.lang {
        Lang::Python => python::emit(spec),
        _ => Err(UnsupportedReason::LangUnsupported),
    }
}
