//! TypeScript per-shape acceptance tests (Phase 13 — Track B JS / TS vertical).
//!
//! Mirrors `tests/javascript_fixtures.rs` against
//! `tests/dynamic_fixtures/typescript/<shape>/`.  TS fixtures use
//! ES-compatible syntax so the harness builder can stage them at
//! `workdir/entry.js` and run them through Node's CommonJS / ESM loader
//! without a separate `tsc` step.

mod common;

#[cfg(feature = "dynamic")]
mod typescript_fixture_tests {
    use crate::common::fixture_harness::{run_shape_fixture_lang_or_skip, Prerequisite};
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::evidence::{EntryKind, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;

    /// Base prereq slice shared by every TS shape: the host must have
    /// `node` on PATH.  Framework-bound shapes extend the slice with a
    /// second `Prerequisite::NodeModuleAvailable("<pkg>")` entry.
    const NODE_REQ: &[Prerequisite] = &[Prerequisite::CommandAvailable("node")];

    fn assert_confirmed(shape: &str, result: &VerifyResult) {
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "{shape}/vuln: expected Confirmed, got {:?} ({:?})",
            result.status,
            result.detail,
        );
    }

    fn assert_not_confirmed(shape: &str, result: &VerifyResult) {
        assert!(
            matches!(
                result.status,
                VerifyStatus::NotConfirmed | VerifyStatus::Inconclusive
            ),
            "{shape}/benign: expected NotConfirmed (or Inconclusive), got {:?} ({:?})",
            result.status,
            result.detail,
        );
        assert_ne!(
            result.status,
            VerifyStatus::Confirmed,
            "{shape}/benign: must not confirm",
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn run(
        requires: &[Prerequisite],
        shape: &str,
        file: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
        kind: EntryKind,
        slot: PayloadSlot,
    ) -> Option<VerifyResult> {
        run_shape_fixture_lang_or_skip(
            requires,
            Lang::TypeScript,
            "typescript",
            shape,
            file,
            func,
            cap,
            sink_line,
            kind,
            slot,
        )
    }

    // ── commonjs_export ─────────────────────────────────────────────────────

    #[test]
    fn commonjs_export_vuln_is_confirmed() {
        let Some(r) = run(
            NODE_REQ,
            "commonjs_export", "vuln.ts", "runPing", Cap::CODE_EXEC, 11,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else { return; };
        assert_confirmed("commonjs_export", &r);
    }

    #[test]
    fn commonjs_export_benign_not_confirmed() {
        let Some(r) = run(
            NODE_REQ,
            "commonjs_export", "benign.ts", "runPing", Cap::CODE_EXEC, 11,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else { return; };
        assert_not_confirmed("commonjs_export", &r);
    }

    // ── async_function ──────────────────────────────────────────────────────

    #[test]
    fn async_function_vuln_is_confirmed() {
        let Some(r) = run(
            NODE_REQ,
            "async_function", "vuln.ts", "runPing", Cap::CODE_EXEC, 15,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else { return; };
        assert_confirmed("async_function", &r);
    }

    #[test]
    fn async_function_benign_not_confirmed() {
        let Some(r) = run(
            NODE_REQ,
            "async_function", "benign.ts", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else { return; };
        assert_not_confirmed("async_function", &r);
    }

    // ── esm_default ─────────────────────────────────────────────────────────

    #[test]
    fn esm_default_vuln_is_confirmed() {
        let Some(r) = run(
            NODE_REQ,
            "esm_default", "vuln.ts", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else { return; };
        assert_confirmed("esm_default", &r);
    }

    #[test]
    fn esm_default_benign_not_confirmed() {
        let Some(r) = run(
            NODE_REQ,
            "esm_default", "benign.ts", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else { return; };
        assert_not_confirmed("esm_default", &r);
    }

    // ── express ─────────────────────────────────────────────────────────────

    #[test]
    fn express_vuln_is_confirmed() {
        let Some(r) = run(
            &[
                Prerequisite::CommandAvailable("node"),
                Prerequisite::NodeModuleAvailable("express"),
            ],
            "express", "vuln.ts", "ping", Cap::CODE_EXEC, 15,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        ) else { return; };
        assert_confirmed("express", &r);
    }

    #[test]
    fn express_benign_not_confirmed() {
        let Some(r) = run(
            &[
                Prerequisite::CommandAvailable("node"),
                Prerequisite::NodeModuleAvailable("express"),
            ],
            "express", "benign.ts", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        ) else { return; };
        assert_not_confirmed("express", &r);
    }

    // ── koa ─────────────────────────────────────────────────────────────────

    #[test]
    fn koa_vuln_is_confirmed() {
        let Some(r) = run(
            &[
                Prerequisite::CommandAvailable("node"),
                Prerequisite::NodeModuleAvailable("koa"),
            ],
            "koa", "vuln.ts", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        ) else { return; };
        assert_confirmed("koa", &r);
    }

    #[test]
    fn koa_benign_not_confirmed() {
        let Some(r) = run(
            &[
                Prerequisite::CommandAvailable("node"),
                Prerequisite::NodeModuleAvailable("koa"),
            ],
            "koa", "benign.ts", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        ) else { return; };
        assert_not_confirmed("koa", &r);
    }

    // ── next_route ──────────────────────────────────────────────────────────

    #[test]
    fn next_route_vuln_is_confirmed() {
        let Some(r) = run(
            &[
                Prerequisite::CommandAvailable("node"),
                Prerequisite::NodeModuleAvailable("next"),
            ],
            "next_route", "vuln.ts", "handler", Cap::CODE_EXEC, 17,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        ) else { return; };
        assert_confirmed("next_route", &r);
    }

    #[test]
    fn next_route_benign_not_confirmed() {
        let Some(r) = run(
            &[
                Prerequisite::CommandAvailable("node"),
                Prerequisite::NodeModuleAvailable("next"),
            ],
            "next_route", "benign.ts", "handler", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        ) else { return; };
        assert_not_confirmed("next_route", &r);
    }

    // ── browser_event (jsdom) ───────────────────────────────────────────────

    #[test]
    fn browser_event_vuln_is_confirmed() {
        let Some(r) = run(
            &[
                Prerequisite::CommandAvailable("node"),
                Prerequisite::NodeModuleAvailable("jsdom"),
            ],
            "browser_event", "vuln.ts", "clickHandler", Cap::HTML_ESCAPE, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else { return; };
        assert_confirmed("browser_event", &r);
    }

    #[test]
    fn browser_event_benign_not_confirmed() {
        let Some(r) = run(
            &[
                Prerequisite::CommandAvailable("node"),
                Prerequisite::NodeModuleAvailable("jsdom"),
            ],
            "browser_event", "benign.ts", "clickHandler", Cap::HTML_ESCAPE, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else { return; };
        assert_not_confirmed("browser_event", &r);
    }
}
