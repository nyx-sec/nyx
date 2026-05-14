//! JavaScript per-shape acceptance tests (Phase 13 — Track B JS / TS vertical).
//!
//! For each [`nyx_scanner::dynamic::lang::js_shared::JsShape`] this suite
//! asserts:
//!
//!   1. The vuln fixture confirms (cmdi / xss oracle fires on the process
//!      backend, sink probe lights up).
//!   2. The benign fixture does NOT confirm.
//!
//! Framework-bound shapes (Express / Koa / Next.js / browser-event under
//! jsdom) skip with an `eprintln!` when the package is unimportable in the
//! host's `node` interpreter — `prepare_node`'s `npm install --no-save`
//! would otherwise hang on a clean offline CI environment.  In a developer
//! workstation with the framework installed globally / via the lockfile,
//! the test attempts the full pipeline.

mod common;

#[cfg(feature = "dynamic")]
mod javascript_fixture_tests {
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
            Lang::JavaScript,
            "javascript",
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
            "commonjs_export", "vuln.js", "runPing", Cap::CODE_EXEC, 11,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("commonjs_export", &r);
    }

    #[test]
    fn commonjs_export_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "commonjs_export", "benign.js", "runPing", Cap::CODE_EXEC, 11,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("commonjs_export", &r);
    }

    // ── async_function ──────────────────────────────────────────────────────

    #[test]
    fn async_function_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "async_function", "vuln.js", "runPing", Cap::CODE_EXEC, 15,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("async_function", &r);
    }

    #[test]
    fn async_function_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "async_function", "benign.js", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("async_function", &r);
    }

    // ── esm_default ─────────────────────────────────────────────────────────

    #[test]
    fn esm_default_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "esm_default", "vuln.js", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("esm_default", &r);
    }

    #[test]
    fn esm_default_benign_not_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        let r = run(
            "esm_default", "benign.js", "runPing", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("esm_default", &r);
    }

    // ── express (framework-bound) ───────────────────────────────────────────

    #[test]
    fn express_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("express") {
            eprintln!("SKIP: express not importable");
            return;
        }
        let r = run(
            "express", "vuln.js", "ping", Cap::CODE_EXEC, 15,
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
            "express", "benign.js", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_not_confirmed("express", &r);
    }

    // ── koa (framework-bound) ───────────────────────────────────────────────

    #[test]
    fn koa_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("koa") {
            eprintln!("SKIP: koa not importable");
            return;
        }
        let r = run(
            "koa", "vuln.js", "ping", Cap::CODE_EXEC, 14,
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
            "koa", "benign.js", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_not_confirmed("koa", &r);
    }

    // ── next_route (framework-bound) ────────────────────────────────────────

    #[test]
    fn next_route_vuln_is_confirmed() {
        if !node_available() { eprintln!("SKIP: node not available"); return; }
        if !node_module_available("next") {
            eprintln!("SKIP: next not importable");
            return;
        }
        let r = run(
            "next_route", "vuln.js", "handler", Cap::CODE_EXEC, 17,
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
            "next_route", "benign.js", "handler", Cap::CODE_EXEC, 14,
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
            "browser_event", "vuln.js", "clickHandler", Cap::HTML_ESCAPE, 14,
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
            "browser_event", "benign.js", "clickHandler", Cap::HTML_ESCAPE, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("browser_event", &r);
    }
}
