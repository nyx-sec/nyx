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
    use crate::common::fixture_harness::run_shape_fixture_lang;
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::evidence::{EntryKind, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;

    fn node_available() -> bool {
        std::process::Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn node_module_available(name: &'static str) -> bool {
        std::process::Command::new("node")
            .arg("-e")
            .arg(format!("require.resolve('{name}')"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

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

    fn run(
        shape: &str,
        file: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
        kind: EntryKind,
        slot: PayloadSlot,
    ) -> VerifyResult {
        run_shape_fixture_lang(
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
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "commonjs_export", "vuln.ts", "runPing", Cap::CODE_EXEC, 11,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("commonjs_export", &r);
    }

    #[test]
    fn commonjs_export_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "commonjs_export", "benign.ts", "runPing", Cap::CODE_EXEC, 11,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("commonjs_export", &r);
    }

    // ── async_function ──────────────────────────────────────────────────────

    #[test]
    fn async_function_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "async_function", "vuln.ts", "runPing", Cap::CODE_EXEC, 15,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("async_function", &r);
    }

    #[test]
    fn async_function_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "async_function", "benign.ts", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("async_function", &r);
    }

    // ── esm_default ─────────────────────────────────────────────────────────

    #[test]
    fn esm_default_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "esm_default", "vuln.ts", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("esm_default", &r);
    }

    #[test]
    fn esm_default_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "esm_default", "benign.ts", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("esm_default", &r);
    }

    // ── express ─────────────────────────────────────────────────────────────

    #[test]
    fn express_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("express") {
            eprintln!("SKIP: express not importable");
            return;
        }
        let r = run(
            "express", "vuln.ts", "ping", Cap::CODE_EXEC, 15,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_confirmed("express", &r);
    }

    #[test]
    fn express_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("express") {
            eprintln!("SKIP: express not importable");
            return;
        }
        let r = run(
            "express", "benign.ts", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_not_confirmed("express", &r);
    }

    // ── koa ─────────────────────────────────────────────────────────────────

    #[test]
    fn koa_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("koa") {
            eprintln!("SKIP: koa not importable");
            return;
        }
        let r = run(
            "koa", "vuln.ts", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_confirmed("koa", &r);
    }

    #[test]
    fn koa_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("koa") {
            eprintln!("SKIP: koa not importable");
            return;
        }
        let r = run(
            "koa", "benign.ts", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_not_confirmed("koa", &r);
    }

    // ── next_route ──────────────────────────────────────────────────────────

    #[test]
    fn next_route_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("next") {
            eprintln!("SKIP: next not importable");
            return;
        }
        let r = run(
            "next_route", "vuln.ts", "handler", Cap::CODE_EXEC, 17,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_confirmed("next_route", &r);
    }

    #[test]
    fn next_route_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("next") {
            eprintln!("SKIP: next not importable");
            return;
        }
        let r = run(
            "next_route", "benign.ts", "handler", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_not_confirmed("next_route", &r);
    }

    // ── browser_event (jsdom) ───────────────────────────────────────────────

    #[test]
    fn browser_event_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("jsdom") {
            eprintln!("SKIP: jsdom not importable");
            return;
        }
        let r = run(
            "browser_event", "vuln.ts", "clickHandler", Cap::HTML_ESCAPE, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("browser_event", &r);
    }

    #[test]
    fn browser_event_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("jsdom") {
            eprintln!("SKIP: jsdom not importable");
            return;
        }
        let r = run(
            "browser_event", "benign.ts", "clickHandler", Cap::HTML_ESCAPE, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("browser_event", &r);
    }
}
