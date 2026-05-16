//! Ruby fixture integration tests (Phase 15 acceptance gate).
//!
//! Per-shape acceptance for the Ruby emitter shapes shipped in Phase 15
//! (Track B Ruby vertical): Sinatra route, Rails action, Rack middleware,
//! and generic controller method.  Each shape ships a `vuln.rb` + `benign.rb`
//! pair under `tests/dynamic_fixtures/ruby/<shape>/`.
//!
//! Prerequisites: skips cleanly when `ruby` is unavailable on the host.
//!
//! Run with: `cargo nextest run --features dynamic --test ruby_fixtures`

mod common;

#[cfg(feature = "dynamic")]
mod phase15_shape_tests {
    use crate::common::fixture_harness::{run_shape_fixture_lang_or_skip, Prerequisite};
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::evidence::{EntryKind, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;

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
    ) -> Option<VerifyResult> {
        // Phase 29 (Track I): structured prerequisite gating replaces
        // the bespoke `ruby_available()` + per-test
        // `eprintln!("SKIP ..."); return;` pattern.
        run_shape_fixture_lang_or_skip(
            &[Prerequisite::CommandAvailable("ruby")],
            Lang::Ruby,
            "ruby",
            shape,
            file,
            func,
            cap,
            sink_line,
            kind,
            slot,
        )
    }

    // ── sinatra_route ────────────────────────────────────────────────────────

    #[test]
    fn sinatra_route_vuln_is_confirmed() {
        let Some(r) = run(
            "sinatra_route", "vuln.rb", "run", Cap::CODE_EXEC, 7,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("sinatra_route", &r);
    }

    #[test]
    fn sinatra_route_benign_not_confirmed() {
        let Some(r) = run(
            "sinatra_route", "benign.rb", "run", Cap::CODE_EXEC, 10,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("sinatra_route", &r);
    }

    // ── rails_action ─────────────────────────────────────────────────────────

    #[test]
    fn rails_action_vuln_is_confirmed() {
        let Some(r) = run(
            "rails_action", "vuln.rb", "index", Cap::CODE_EXEC, 17,
            EntryKind::HttpRoute, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        ) else {
            return;
        };
        assert_confirmed("rails_action", &r);
    }

    #[test]
    fn rails_action_benign_not_confirmed() {
        let Some(r) = run(
            "rails_action", "benign.rb", "index", Cap::CODE_EXEC, 20,
            EntryKind::HttpRoute, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        ) else {
            return;
        };
        assert_not_confirmed("rails_action", &r);
    }

    // ── rack_middleware ──────────────────────────────────────────────────────

    #[test]
    fn rack_middleware_vuln_is_confirmed() {
        let Some(r) = run(
            "rack_middleware", "vuln.rb", "call", Cap::CODE_EXEC, 9,
            EntryKind::HttpRoute, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        ) else {
            return;
        };
        assert_confirmed("rack_middleware", &r);
    }

    #[test]
    fn rack_middleware_benign_not_confirmed() {
        let Some(r) = run(
            "rack_middleware", "benign.rb", "call", Cap::CODE_EXEC, 11,
            EntryKind::HttpRoute, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        ) else {
            return;
        };
        assert_not_confirmed("rack_middleware", &r);
    }

    // ── controller_method ────────────────────────────────────────────────────

    #[test]
    fn controller_method_vuln_is_confirmed() {
        let Some(r) = run(
            "controller_method", "vuln.rb", "authenticate", Cap::CODE_EXEC, 7,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("controller_method", &r);
    }

    #[test]
    fn controller_method_benign_not_confirmed() {
        let Some(r) = run(
            "controller_method", "benign.rb", "authenticate", Cap::CODE_EXEC, 10,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("controller_method", &r);
    }
}
