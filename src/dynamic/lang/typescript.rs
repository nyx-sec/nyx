//! TypeScript harness emitter.
//!
//! Shares the per-shape dispatch in [`crate::dynamic::lang::js_shared`] with
//! the JavaScript emitter — the runtime is Node.js in both cases.  The only
//! divergence is the entry filename: TypeScript fixtures are staged at
//! `workdir/entry.ts` so the staged source preserves its extension for
//! human-readable repro bundles.  Node's CommonJS loader honours an
//! extension-less `require('./entry')`, so the harness can load either
//! `entry.js` or `entry.ts` without a separate typed-loader step.
//!
//! Phase 13 (Track B JS + TS vertical) introduced TS-specific shapes
//! (Next.js route handlers, `tsx` browser modules under jsdom).  The shape
//! detector in `js_shared` fires identically against TS or JS source — TS
//! fixtures use ES-compatible syntax with optional type annotations the
//! runtime ignores.

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{js_shared, ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for TypeScript.
pub struct TypeScriptEmitter;

/// Source of the `__nyx_probe` shim for TypeScript harnesses.
pub fn probe_shim() -> &'static str {
    js_shared::probe_shim()
}

impl LangEmitter for TypeScriptEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        js_shared::emit(spec, true)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        js_shared::SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "typescript emitter supports {supported:?} (shared dispatch with javascript via `js_shared`); this finding's enclosing context is `EntryKind::{attempted}` — see Phase 13 shape dispatch",
            supported = js_shared::SUPPORTED,
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        js_shared::materialize_node(env)
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        js_shared::chain_step(prev_output, /* typescript = */ true, terminal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{HarnessSpec, PayloadSlot, SpecDerivationStrategy};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(kind: EntryKind) -> HarnessSpec {
        HarnessSpec {
            finding_id: "ts000000000001".into(),
            entry_file: "src/app.ts".into(),
            entry_name: "login".into(),
            entry_kind: kind,
            lang: Lang::TypeScript,
            toolchain_id: "node-20".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: "src/app.ts".into(),
            sink_line: 12,
            spec_hash: "ts000000000001ab".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
        }
    }

    #[test]
    fn entry_kinds_supported_is_non_empty_and_includes_http_route() {
        assert!(!TypeScriptEmitter.entry_kinds_supported().is_empty());
        assert!(TypeScriptEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::HttpRoute));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = TypeScriptEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("Phase 13"));
    }

    #[test]
    fn typescript_emit_stages_entry_at_entry_js_for_node_resolution() {
        let h = TypeScriptEmitter.emit(&make_spec(EntryKind::Function)).unwrap();
        // TS fixtures use ES-compatible syntax; the workdir layout matches
        // JavaScript so Node's CJS `require('./entry')` resolves without an
        // extension-loader hook.  See js_shared::entry_subpath_for_shape.
        assert_eq!(h.entry_subpath.as_deref(), Some("entry.js"));
        assert_eq!(h.filename, "harness.js");
    }
}
