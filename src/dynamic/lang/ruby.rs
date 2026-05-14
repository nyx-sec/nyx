//! Ruby harness emitter (stub).
//!
//! No harness source is generated yet — `emit` returns
//! [`UnsupportedReason::LangUnsupported`].  The module exists so that
//! [`crate::dynamic::lang::entry_kinds_supported`] can advertise the entry
//! kinds Track B will deliver (Phase 15: Sinatra route, Rails action, Rack
//! middleware, generic controller method) and so the verifier can surface
//! a structured `Inconclusive(EntryKindUnsupported { … })` instead of
//! silently dropping Ruby findings.

use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for Ruby.
pub struct RubyEmitter;

/// Entry kinds the Ruby emitter intends to support once Phase 15 lands.
/// Advertised pre-implementation so the verifier can route findings into
/// `Inconclusive(EntryKindUnsupported)` rather than `Unsupported`.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

impl LangEmitter for RubyEmitter {
    fn emit(&self, _spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        Err(UnsupportedReason::LangUnsupported)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "ruby emitter is a stub; once Phase 15 (Track B Ruby vertical) lands it will support {SUPPORTED:?} plus Sinatra / Rails / Rack route shapes — attempted `EntryKind::{attempted}`"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!RubyEmitter.entry_kinds_supported().is_empty());
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = RubyEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("Phase 15"));
    }

    #[test]
    fn emit_returns_lang_unsupported() {
        let spec = HarnessSpec {
            finding_id: "0".into(),
            entry_file: "x.rb".into(),
            entry_name: "f".into(),
            entry_kind: EntryKind::Function,
            lang: crate::symbol::Lang::Ruby,
            toolchain_id: "ruby-3".into(),
            payload_slot: crate::dynamic::spec::PayloadSlot::Param(0),
            expected_cap: crate::labels::Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "x.rb".into(),
            sink_line: 1,
            spec_hash: "0".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        };
        assert_eq!(
            RubyEmitter.emit(&spec).unwrap_err(),
            UnsupportedReason::LangUnsupported
        );
    }
}
