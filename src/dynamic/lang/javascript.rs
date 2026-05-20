//! JavaScript harness emitter.
//!
//! After Phase 13 (Track B JS + TS vertical) the per-shape dispatch lives in
//! [`crate::dynamic::lang::js_shared`].  This module is the typed surface for
//! `Lang::JavaScript`: registers the [`JavaScriptEmitter`] in the dispatch
//! table, advertises the supported [`EntryKind`] set, and forwards
//! `emit` / `materialize_runtime` calls to the shared module.
//!
//! Payload slot support (handled by `js_shared::emit`):
//! - [`PayloadSlot::Param`] — n-th positional argument.
//! - [`PayloadSlot::EnvVar`] — set env var before calling.
//! - [`PayloadSlot::Stdin`] — pipe payload to `process.stdin`.
//! - [`PayloadSlot::QueryParam`] — HTTP-shaped query param (Express / Koa / Next).
//! - [`PayloadSlot::HttpBody`] — HTTP body (Express / Koa / Next).
//! - [`PayloadSlot::Argv`] — coerced to positional `Param(0)` by build_call.

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{js_shared, ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec};
use crate::evidence::UnsupportedReason;

pub use js_shared::{detect_shape, materialize_node, probe_shim, JsShape};

/// Zero-sized [`LangEmitter`] handle for JavaScript.
pub struct JavaScriptEmitter;

impl LangEmitter for JavaScriptEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        js_shared::SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "javascript emitter supports {supported:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 13 / 19 / 20 / 21 shape dispatch in `js_shared`",
            supported = js_shared::SUPPORTED,
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_node(env)
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        js_shared::chain_step(prev_output, /* typescript = */ false, terminal)
    }
}

/// Emit a JS harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    js_shared::emit(spec, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "js000000000001".into(),
            entry_file: "src/app.js".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::JavaScript,
            toolchain_id: "node-20".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/app.js".into(),
            sink_line: 15,
            spec_hash: "js000000000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("NYX_PAYLOAD"));
        assert!(harness.source.contains("require"));
        assert!(harness.source.contains("login"));
        assert_eq!(harness.filename, "harness.js");
        assert_eq!(harness.command, vec!["node", "harness.js"]);
    }

    #[test]
    fn emit_param_index_0() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("_entry.login(payload)"));
    }

    #[test]
    fn emit_param_index_1() {
        let spec = make_spec(PayloadSlot::Param(1));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("_entry.login('', payload)"));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("DB_HOST".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("process.env[\"DB_HOST\"] = payload"));
    }

    #[test]
    fn emit_stdin_slot() {
        let spec = make_spec(PayloadSlot::Stdin);
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("Readable"));
        assert!(harness.source.contains("process.stdin"));
    }

    #[test]
    fn emit_http_body_now_supported_for_express_shape() {
        let mut spec = make_spec(PayloadSlot::HttpBody);
        spec.entry_kind = EntryKind::HttpRoute;
        let h = emit(&spec).unwrap();
        assert_eq!(h.filename, "harness.js");
    }

    #[test]
    fn emit_entry_subpath_default_is_entry_js() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("entry.js".to_owned()));
    }

    #[test]
    fn entry_kinds_supported_includes_http_and_cli_after_phase_13() {
        let kinds = JavaScriptEmitter.entry_kinds_supported();
        assert!(kinds.contains(&EntryKindTag::Function));
        assert!(kinds.contains(&EntryKindTag::HttpRoute));
        assert!(kinds.contains(&EntryKindTag::CliSubcommand));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = JavaScriptEmitter.entry_kind_hint(EntryKindTag::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("Phase 13"));
    }

}
