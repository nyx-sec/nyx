//! TypeScript harness emitter.
//!
//! Today TypeScript shares the JS emitter — `tsc` is not invoked; the runner
//! treats `.ts` / `.tsx` / `.mts` / `.cts` files as Node-compatible because
//! every shape we currently emit (free functions, `module.exports`-style
//! handlers) is identical at the runtime level after type erasure.  This
//! module exists so the [`crate::dynamic::lang::LangEmitter`] dispatch table
//! has a discoverable per-language handle and so callers can call
//! `entry_kinds_supported(Lang::TypeScript)` symmetrically with the other
//! languages — the actual `emit` body delegates to
//! [`crate::dynamic::lang::javascript::emit`].
//!
//! Phase 13 (Track B JS + TS vertical) introduces TS-specific shapes
//! (Next.js route handlers, `tsx` browser modules under jsdom).  When those
//! land, the supported list / hint shift here without affecting the JS
//! emitter.

use crate::dynamic::lang::{javascript, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for TypeScript.
pub struct TypeScriptEmitter;

/// Entry kinds the TypeScript emitter currently understands. Same as JS until
/// Phase 13 introduces TS-specific shapes (Next.js route handlers, `tsx`
/// browser modules).
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

/// Source of the `__nyx_probe` shim for TypeScript harnesses.
///
/// Delegates to [`crate::dynamic::lang::javascript::probe_shim`] — the
/// runtime is Node.js in both cases, so the JSON-emit shim is identical
/// after type erasure.
pub fn probe_shim() -> &'static str {
    javascript::probe_shim()
}

impl LangEmitter for TypeScriptEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        javascript::emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "typescript emitter supports {SUPPORTED:?} (delegates to the JavaScript emitter); this finding's enclosing context is `EntryKind::{attempted}` — Track B will add Next.js / jsdom shapes in phase 13"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!TypeScriptEmitter.entry_kinds_supported().is_empty());
        assert!(TypeScriptEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::Function));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = TypeScriptEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("phase 13"));
    }
}
