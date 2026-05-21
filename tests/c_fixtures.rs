//! C fixture integration tests (Phase 16 acceptance gate).
//!
//! Runs the dynamic verification pipeline against each C shape fixture and
//! asserts the expected verdict. Requires `--features dynamic` and `cc` on
//! PATH (override via `NYX_CC_BIN`).
//!
//! File layout per shape:
//! ```text
//! tests/dynamic_fixtures/c/<shape>/{vuln,benign}.c
//! ```
//!
//! Run with: `cargo nextest run --features dynamic --test c_fixtures`

mod common;

#[cfg(feature = "dynamic")]
mod c_fixture_tests {
    use crate::common::fixture_harness::{Prerequisite, run_shape_fixture_lang_or_skip};
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::evidence::{EntryKind, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;

    const CC_REQ: &[Prerequisite] = &[Prerequisite::CommandAvailableEnvOverride {
        env_var: "NYX_CC_BIN",
        default: "cc",
    }];

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
        shape: &str,
        file: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
        kind: EntryKind,
        slot: PayloadSlot,
    ) -> Option<VerifyResult> {
        run_shape_fixture_lang_or_skip(
            CC_REQ,
            Lang::C,
            "c",
            shape,
            file,
            func,
            cap,
            sink_line,
            kind,
            slot,
        )
    }

    // ── main_argv ───────────────────────────────────────────────────────────

    #[test]
    fn main_argv_vuln_is_confirmed() {
        let Some(r) = run(
            "main_argv",
            "vuln.c",
            "nyx_entry_main",
            Cap::CODE_EXEC,
            23,
            EntryKind::CliSubcommand,
            PayloadSlot::Argv(0),
        ) else {
            return;
        };
        assert_confirmed("main_argv", &r);
    }

    #[test]
    fn main_argv_benign_not_confirmed() {
        let Some(r) = run(
            "main_argv",
            "benign.c",
            "nyx_entry_main",
            Cap::CODE_EXEC,
            11,
            EntryKind::CliSubcommand,
            PayloadSlot::Argv(0),
        ) else {
            return;
        };
        assert_not_confirmed("main_argv", &r);
    }

    // ── libfuzzer ───────────────────────────────────────────────────────────

    #[test]
    fn libfuzzer_vuln_is_confirmed() {
        let Some(r) = run(
            "libfuzzer",
            "vuln.c",
            "LLVMFuzzerTestOneInput",
            Cap::CODE_EXEC,
            16,
            EntryKind::LibraryApi,
            PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("libfuzzer", &r);
    }

    #[test]
    fn libfuzzer_benign_not_confirmed() {
        let Some(r) = run(
            "libfuzzer",
            "benign.c",
            "LLVMFuzzerTestOneInput",
            Cap::CODE_EXEC,
            10,
            EntryKind::LibraryApi,
            PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("libfuzzer", &r);
    }

    // ── free_fn ─────────────────────────────────────────────────────────────

    #[test]
    fn free_fn_vuln_is_confirmed() {
        let Some(r) = run(
            "free_fn",
            "vuln.c",
            "run",
            Cap::CODE_EXEC,
            15,
            EntryKind::Function,
            PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("free_fn", &r);
    }

    #[test]
    fn free_fn_benign_not_confirmed() {
        let Some(r) = run(
            "free_fn",
            "benign.c",
            "run",
            Cap::CODE_EXEC,
            10,
            EntryKind::Function,
            PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("free_fn", &r);
    }
}
