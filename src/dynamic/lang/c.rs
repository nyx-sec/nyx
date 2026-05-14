//! C harness emitter (stub).
//!
//! No harness source is generated yet — `emit` returns
//! [`UnsupportedReason::LangUnsupported`].  The module exists so that
//! [`crate::dynamic::lang::entry_kinds_supported`] can advertise the entry
//! kinds Track B will deliver (Phase 16: `main(argc, argv)`,
//! `LLVMFuzzerTestOneInput`, free functions with `(const char*, size_t)` or
//! `(int, char**)` shapes) and so the verifier can surface
//! `Inconclusive(EntryKindUnsupported { … })` instead of dropping C findings.

use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for C.
pub struct CEmitter;

/// Entry kinds the C emitter intends to support once Phase 16 lands.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

impl LangEmitter for CEmitter {
    fn emit(&self, _spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        Err(UnsupportedReason::LangUnsupported)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "c emitter is a stub; once Phase 16 (Track B Rust + C/C++ vertical) lands it will support {SUPPORTED:?} plus libFuzzer + main(argc, argv) shapes — attempted `EntryKind::{attempted}`"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!CEmitter.entry_kinds_supported().is_empty());
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = CEmitter.entry_kind_hint(EntryKind::LibraryApi);
        assert!(hint.contains("LibraryApi"));
        assert!(hint.contains("Phase 16"));
    }
}
