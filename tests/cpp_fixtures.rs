//! C++ fixture integration tests (Phase 16 acceptance gate).
//!
//! Runs the dynamic verification pipeline against each C++ shape fixture
//! and asserts the expected verdict. Requires `--features dynamic` and
//! `c++` on PATH (override via `NYX_CXX_BIN`).
//!
//! File layout per shape:
//! ```text
//! tests/dynamic_fixtures/cpp/<shape>/{vuln,benign}.cpp
//! ```
//!
//! Run with: `cargo nextest run --features dynamic --test cpp_fixtures`

mod common;

#[cfg(feature = "dynamic")]
mod cpp_fixture_tests {
    use crate::common::fixture_harness::run_shape_fixture_lang;
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::evidence::{EntryKind, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;

    fn cxx_available() -> bool {
        let bin = std::env::var("NYX_CXX_BIN").unwrap_or_else(|_| "c++".to_owned());
        std::process::Command::new(&bin)
            .arg("--version")
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
            Lang::Cpp, "cpp", shape, file, func, cap, sink_line, kind, slot,
        )
    }

    // ── main_argv ───────────────────────────────────────────────────────────

    #[test]
    fn main_argv_vuln_is_confirmed() {
        if !cxx_available() {
            eprintln!("SKIP: c++ not available");
            return;
        }
        let r = run(
            "main_argv", "vuln.cpp", "nyx_entry_main", Cap::CODE_EXEC, 16,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        );
        assert_confirmed("main_argv", &r);
    }

    #[test]
    fn main_argv_benign_not_confirmed() {
        if !cxx_available() {
            eprintln!("SKIP: c++ not available");
            return;
        }
        let r = run(
            "main_argv", "benign.cpp", "nyx_entry_main", Cap::CODE_EXEC, 11,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        );
        assert_not_confirmed("main_argv", &r);
    }

    // ── libfuzzer ───────────────────────────────────────────────────────────

    #[test]
    fn libfuzzer_vuln_is_confirmed() {
        if !cxx_available() {
            eprintln!("SKIP: c++ not available");
            return;
        }
        let r = run(
            "libfuzzer", "vuln.cpp", "LLVMFuzzerTestOneInput", Cap::CODE_EXEC, 15,
            EntryKind::LibraryApi, PayloadSlot::Param(0),
        );
        assert_confirmed("libfuzzer", &r);
    }

    #[test]
    fn libfuzzer_benign_not_confirmed() {
        if !cxx_available() {
            eprintln!("SKIP: c++ not available");
            return;
        }
        let r = run(
            "libfuzzer", "benign.cpp", "LLVMFuzzerTestOneInput", Cap::CODE_EXEC, 10,
            EntryKind::LibraryApi, PayloadSlot::Param(0),
        );
        assert_not_confirmed("libfuzzer", &r);
    }

    // ── free_fn ─────────────────────────────────────────────────────────────

    #[test]
    fn free_fn_vuln_is_confirmed() {
        if !cxx_available() {
            eprintln!("SKIP: c++ not available");
            return;
        }
        let r = run(
            "free_fn", "vuln.cpp", "run", Cap::CODE_EXEC, 12,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("free_fn", &r);
    }

    #[test]
    fn free_fn_benign_not_confirmed() {
        if !cxx_available() {
            eprintln!("SKIP: c++ not available");
            return;
        }
        let r = run(
            "free_fn", "benign.cpp", "run", Cap::CODE_EXEC, 10,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("free_fn", &r);
    }
}
