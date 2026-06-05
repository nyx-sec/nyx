//! Hostile-input / resource-exhaustion regression tests.
//!
//! Nyx scans untrusted repositories, so every file the scanner picks up is
//! potentially adversarial: arbitrarily large, pathologically nested,
//! binary-ish, or deliberately crafted to wedge tree-sitter or the CFG
//! builder.  These tests exercise the user-facing size cap
//! (`scanner.max_file_size_mb`, default 16 MiB, enforced at the walker),
//! the per-file parse timeout (`analysis.engine.parse_timeout_ms`, default
//! 10 s), and
//! verify that the scanner survives several representative stress inputs
//! without panicking, stack-overflowing, or hanging CI.
//!
//! All tests stay well under the 10 s taint-termination guard used elsewhere
//! so they are safe for the default test job.  Keep file sizes modest so
//! CI runners with limited RAM/disk are not penalised.

use nyx_scanner::ast::run_rules_on_bytes;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// Match the production rayon worker stack size (`performance.rayon_thread_stack_size`).
/// Tests that exercise recursive CFG construction must run here, not on the
/// default 2 MiB test thread, so they represent the real scan environment.
const PROD_STACK_SIZE: usize = 8 * 1024 * 1024;

/// Run `f` on a dedicated thread with a production-sized stack.  Panics in
/// `f` are propagated so the test fails with the original message.
fn run_on_prod_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    thread::Builder::new()
        .stack_size(PROD_STACK_SIZE)
        .name("hostile-input-prod-stack".into())
        .spawn(f)
        .expect("spawn test thread")
        .join()
        .expect("test thread panicked")
}

// ───────────────────────────────────────────────────────────────────────────
//  Helpers
// ───────────────────────────────────────────────────────────────────────────

/// Minimal config tuned for deterministic, single-threaded scans in CI.
fn hostile_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 8;
    cfg.performance.channel_multiplier = 1;
    cfg
}

/// Run a closure and fail the test if it does not complete within `budget`.
/// Used to keep these regression tests from silently turning into CI hangs
/// if a bound regresses.
fn with_time_budget<F, R>(budget: Duration, label: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed();
    assert!(
        elapsed < budget,
        "{label} took {elapsed:?}, exceeded budget {budget:?}",
    );
    out
}

// ───────────────────────────────────────────────────────────────────────────
//  File-size hardening (walker-level)
// ───────────────────────────────────────────────────────────────────────────

/// The walker's `max_file_size_mb` filter must drop oversize files before
/// the pipeline ever opens them.  This is the sole file-size gate: once a
/// file is past the walker, the analysis pipeline does not re-check its
/// size, `max_file_size_mb = null` means truly unlimited parsing.  The
/// pattern here (explicit `Some(1)`) is the interface every downstream
/// caller can use to tighten the default further.
#[test]
fn walker_max_file_size_drops_oversize_files_before_scan() {
    use nyx_scanner::scan_no_index;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    std::fs::write(root.join("small.js"), b"var x = 1;\n").unwrap();
    let big = vec![b'x'; 3 * 1024 * 1024];
    std::fs::write(root.join("big.js"), big).unwrap();

    let mut cfg = hostile_cfg();
    cfg.scanner.max_file_size_mb = Some(1); // 1 MiB, drops big.js, keeps small.js

    let diags =
        scan_no_index(root, &cfg).expect("scan should succeed even with oversize files present");
    assert!(
        diags.iter().all(|d| !d.path.ends_with("big.js")),
        "big.js should have been filtered by walker, got: {diags:?}",
    );
}

/// Release-hardening regression: the default `ScannerConfig` must carry a
/// finite ceiling so a fresh install never tries to parse a multi-gigabyte
/// file from an untrusted repo.  This test does not hard-code the exact
/// value, the property is that the default is *not* unlimited.
#[test]
fn default_config_has_finite_max_file_size() {
    let cfg = Config::default();
    assert!(
        cfg.scanner.max_file_size_mb.is_some(),
        "release default must not be unlimited; got {:?}",
        cfg.scanner.max_file_size_mb,
    );
    let limit = cfg.scanner.max_file_size_mb.unwrap();
    assert!(
        (1..=64).contains(&limit),
        "default file-size cap should live in [1, 64] MiB, got {limit} MiB",
    );
}

/// A file above the default cap must be dropped by the walker when the
/// config is left at its defaults.  End-to-end version of the property
/// asserted above.
#[test]
fn default_config_drops_file_above_cap() {
    use nyx_scanner::scan_no_index;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("small.js"), b"var x = 1;\n").unwrap();

    // Write a file larger than the default cap.  Size = default + 1 MiB so
    // the test does not spuriously fail if the default is adjusted later.
    let default_mb = Config::default()
        .scanner
        .max_file_size_mb
        .expect("default cap must be set");
    let oversize = ((default_mb + 1) as usize) * 1024 * 1024;
    let mut big = b"// big generated file\n".to_vec();
    big.resize(oversize, b' ');
    std::fs::write(root.join("big.js"), &big).unwrap();

    // Use the release default cap explicitly so the intent is clear.
    let mut cfg = hostile_cfg();
    cfg.scanner.max_file_size_mb = Config::default().scanner.max_file_size_mb;

    let diags = with_time_budget(Duration::from_secs(10), "default-cap scan", || {
        scan_no_index(root, &cfg).expect("scan must succeed with oversize file present")
    });
    assert!(
        diags.iter().all(|d| !d.path.ends_with("big.js")),
        "default cap should have filtered big.js: got {diags:?}",
    );
}

/// Operators who explicitly set `max_file_size_mb = null` must actually get
/// unlimited scanning, no silent hard cap overrides their decision.  This
/// locks in the contract: "unlimited means unlimited, trust the operator."
/// The test uses a deliberately unsafe-looking JS source and asserts that
/// the finding surfaces only in the unlimited run.
#[test]
fn explicit_unlimited_lifts_size_cap() {
    use nyx_scanner::scan_no_index;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Build a 2 MiB file with a detectable vulnerability at the top.
    // tight_cap (1 MiB) must hide it; unlimited must surface it.
    let mut bytes = b"const cp = require('child_process');\n\
                      function run(cmd){ cp.exec(cmd); }\n"
        .to_vec();
    bytes.resize(2 * 1024 * 1024, b'\n');
    std::fs::write(root.join("big.js"), &bytes).unwrap();

    let mut cfg = hostile_cfg();

    // 1 MiB cap, must drop big.js entirely.
    cfg.scanner.max_file_size_mb = Some(1);
    let tight = scan_no_index(root, &cfg).expect("tight-cap scan must succeed");
    assert!(
        tight.iter().all(|d| !d.path.ends_with("big.js")),
        "sanity: tight cap must have dropped big.js: {tight:?}",
    );

    // Explicit unlimited, the same file must now be visible to the
    // scanner.  Any pipeline exception would surface as a non-success.
    cfg.scanner.max_file_size_mb = None;
    let unlimited = with_time_budget(Duration::from_secs(20), "unlimited scan", || {
        scan_no_index(root, &cfg).expect("explicit-unlimited scan must succeed")
    });
    assert!(
        unlimited.iter().any(|d| d.path.ends_with("big.js")),
        "explicit unlimited must scan big.js; got {unlimited:?}",
    );
}

// ───────────────────────────────────────────────────────────────────────────
//  Binary / junk / encoding hardening
// ───────────────────────────────────────────────────────────────────────────

/// Random binary noise (NUL-heavy) must be detected and skipped quickly.
#[test]
fn binary_null_heavy_input_is_skipped() {
    // 256 KiB with every third byte NUL → well above the 1% NUL threshold.
    let mut bytes = vec![0xCCu8; 256 * 1024];
    for i in (0..bytes.len()).step_by(3) {
        bytes[i] = 0;
    }

    let path = Path::new("junk.c");
    let cfg = hostile_cfg();
    let diags = with_time_budget(Duration::from_secs(2), "binary skip", || {
        run_rules_on_bytes(&bytes, path, &cfg, None, None).expect("binary file should not error")
    });
    assert!(
        diags.is_empty(),
        "binary-looking files must be skipped, got {} diags",
        diags.len()
    );
}

/// Invalid UTF-8 in a recognised source extension must not panic.
/// tree-sitter can operate on raw bytes; we just check that it survives.
/// Budget widened from 2 s to 10 s after the pitboss parallel `cargo test`
/// invocation surfaced ~2.8 s wall time under shared-runner CPU pressure
/// even though the isolated test runs well under 100 ms.  The point is
/// to catch a runaway, not to benchmark, so 10 s leaves clear headroom
/// without masking a real regression.
#[test]
fn invalid_utf8_does_not_panic() {
    let bytes = b"\xff\xfe\xfd\xfc\n\xde\xad\xbe\xef\n// trailing\n".to_vec();
    let path = Path::new("junk.rs");
    let cfg = hostile_cfg();
    let _ = with_time_budget(Duration::from_secs(10), "invalid utf8", || {
        run_rules_on_bytes(&bytes, path, &cfg, None, None).expect("invalid UTF-8 should not error")
    });
}

/// An empty file must produce no findings and no errors.  Trivial, but it
/// was a historical source of div-by-zero bugs in `is_binary`.
#[test]
fn empty_file_is_noop() {
    let path = Path::new("empty.js");
    let cfg = hostile_cfg();
    let diags = run_rules_on_bytes(b"", path, &cfg, None, None).expect("empty file should be ok");
    assert!(diags.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
//  Structural stress: long lines and deep nesting
// ───────────────────────────────────────────────────────────────────────────

/// A source file consisting of a single extremely long line must parse
/// without blowing up.  Minified bundles routinely hit this shape.  We
/// model it as ~10 000 independent short statements on one line (roughly
/// what you see after bundler output) rather than one 500k-deep
/// right-associative expression, the latter is a separate stress case
/// dominated by recursive descent and not representative of real input.
///
/// Generous debug-build budget (40 s) because the full analysis pipeline
/// runs on every statement; release builds are an order of magnitude
/// faster.  The point is to guard against regressions that are
/// super-linear in statement count, not to benchmark.  Budget widened
/// from 20 s after the pitboss parallel `cargo test` invocation surfaced
/// 24-25 s wall time under shared-runner CPU pressure even though the
/// isolated test runs in ~3.7 s.
#[test]
fn very_long_single_line_parses() {
    run_on_prod_stack(|| {
        let mut s = String::with_capacity(128 * 1024);
        for i in 0..10_000 {
            s.push_str(&format!("var a{i}=1;"));
        }
        s.push('\n');

        let path = Path::new("long_line.js");
        let cfg = hostile_cfg();
        let _ = with_time_budget(Duration::from_secs(40), "long line parse", || {
            run_rules_on_bytes(s.as_bytes(), path, &cfg, None, None)
                .expect("long-line file should parse")
        });
    });
}

/// Deeply-nested parentheses exercise the recursive descent in tree-sitter
/// and the recursive `build_sub` in `cfg::build_cfg`.  Runs on a thread
/// sized to match the production rayon stack so the test environment
/// matches the real scan environment.  500 levels leaves comfortable
/// headroom; a regression that doubled the per-frame cost would trip this.
#[test]
fn deeply_nested_parens_do_not_stack_overflow() {
    run_on_prod_stack(|| {
        const DEPTH: usize = 500;
        let mut s = String::with_capacity(DEPTH * 4);
        s.push_str("var x = ");
        for _ in 0..DEPTH {
            s.push('(');
        }
        s.push('1');
        for _ in 0..DEPTH {
            s.push(')');
        }
        s.push_str(";\n");

        let path = Path::new("deep_parens.js");
        let cfg = hostile_cfg();
        let _ = with_time_budget(Duration::from_secs(10), "deep parens parse", || {
            run_rules_on_bytes(s.as_bytes(), path, &cfg, None, None)
                .expect("deeply nested parens should parse")
        });
    });
}

/// Deeply-nested `if` statements are the classical stress case for the CFG
/// builder.  Each `if` frame in `build_sub` is ~10 KiB on debug builds, so
/// 100 levels fits comfortably inside the production 8 MiB stack with room
/// for the rest of the analysis pipeline above it.  The goal is not to
/// probe the absolute limit, it is to lock in that a realistic generated-
/// code depth does not crash the scanner.
#[test]
fn deeply_nested_if_statements_do_not_stack_overflow() {
    run_on_prod_stack(|| {
        const DEPTH: usize = 100;
        let mut s = String::with_capacity(DEPTH * 16);
        s.push_str("function f(x){\n");
        for i in 0..DEPTH {
            for _ in 0..i {
                s.push(' ');
            }
            s.push_str("if (x) {\n");
        }
        for i in (0..DEPTH).rev() {
            for _ in 0..i {
                s.push(' ');
            }
            s.push_str("}\n");
        }
        s.push_str("}\n");

        let path = Path::new("deep_if.js");
        let cfg = hostile_cfg();
        let _ = with_time_budget(Duration::from_secs(10), "deep if parse", || {
            run_rules_on_bytes(s.as_bytes(), path, &cfg, None, None)
                .expect("deeply nested ifs should parse")
        });
    });
}

/// Lots of small functions in one file stresses the pass-1/pass-2 bookkeeping
/// (summary extraction, callgraph build).  2 000 functions is cheap but
/// plausible for generated code.  Budget widened from 15 s after the
/// pitboss parallel `cargo test` invocation surfaced 15.3 s under
/// shared-runner CPU pressure even though the isolated test runs in
/// ~3.7 s.
#[test]
fn many_small_functions_do_not_explode() {
    let mut s = String::with_capacity(2000 * 32);
    for i in 0..2000 {
        s.push_str(&format!("function f{i}(x) {{ return x + {i}; }}\n"));
    }

    let path = Path::new("many_funcs.js");
    let cfg = hostile_cfg();
    let _ = with_time_budget(Duration::from_secs(30), "many-funcs scan", || {
        run_rules_on_bytes(s.as_bytes(), path, &cfg, None, None)
            .expect("many-functions file should scan")
    });
}

// ───────────────────────────────────────────────────────────────────────────
//  End-to-end: hostile directory scan
// ───────────────────────────────────────────────────────────────────────────

/// A tempdir mixing several adversarial files must scan to completion in
/// bounded time and produce a well-formed diag list.  This is the smoke
/// test most likely to catch a regression that composes badly across files.
#[test]
fn scan_of_mixed_hostile_directory_is_bounded() {
    use nyx_scanner::scan_no_index;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Legitimate file so the scan has real work to do.
    std::fs::write(
        root.join("normal.js"),
        b"const cp = require('child_process');\n\
          function run(cmd) { cp.exec(cmd); }\n",
    )
    .unwrap();

    // Binary noise.
    let mut junk = vec![0xAAu8; 64 * 1024];
    for i in (0..junk.len()).step_by(3) {
        junk[i] = 0;
    }
    std::fs::write(root.join("junk.c"), junk).unwrap();

    // Long single line.
    let mut long = b"var y = ".to_vec();
    long.extend(std::iter::repeat_n(b'a', 256 * 1024));
    long.extend_from_slice(b";\n");
    std::fs::write(root.join("long.js"), &long).unwrap();

    // Deeply-nested parens.
    let mut deep = String::from("var z = ");
    for _ in 0..200 {
        deep.push('(');
    }
    deep.push('1');
    for _ in 0..200 {
        deep.push(')');
    }
    deep.push_str(";\n");
    std::fs::write(root.join("deep.js"), deep).unwrap();

    // Oversize-for-walker (2 MiB; walker configured to drop it).
    let big = vec![b'x'; 2 * 1024 * 1024];
    std::fs::write(root.join("big.js"), big).unwrap();

    let mut cfg = hostile_cfg();
    cfg.scanner.max_file_size_mb = Some(1);

    let diags = with_time_budget(Duration::from_secs(30), "hostile dir scan", || {
        scan_no_index(root, &cfg).expect("scan must not fail on hostile inputs")
    });

    // The walker must drop big.js.
    assert!(
        diags.iter().all(|d| !d.path.ends_with("big.js")),
        "walker should have filtered big.js"
    );
    // The legitimate file should still yield its cmdi finding.
    assert!(
        diags.iter().any(|d| d.path.ends_with("normal.js")),
        "normal.js should still produce findings: {diags:?}",
    );
}

// ───────────────────────────────────────────────────────────────────────────
//  Symlink loops, infinite-loop resistance
// ───────────────────────────────────────────────────────────────────────────

/// A self-referencing symlink (`a/self -> ../a`) is a classic hostile-input
/// shape: a naive follow-symlinks walker will recurse forever.  The `ignore`
/// crate's `WalkBuilder` handles cycles, but the scanner wraps that behind
/// its own canonicalization + containment check; a regression that re-enables
/// a cyclic walk would hang CI indefinitely.  The test enforces a hard wall-
/// clock budget so a hang is caught as a timeout rather than as silent CI
/// stall.
#[cfg(unix)]
#[test]
fn symlink_loop_does_not_hang_with_follow() {
    use nyx_scanner::scan_no_index;
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Real file so the scan has legitimate work to do.
    std::fs::write(root.join("real.js"), b"var x = 1;\n").unwrap();

    // Nested directory with a self-referencing symlink: `a/self -> ../a`
    // expands infinitely under a naive follow-symlinks walk.
    let a = root.join("a");
    std::fs::create_dir(&a).unwrap();
    std::fs::write(a.join("inside.js"), b"var y = 2;\n").unwrap();
    symlink("../a", a.join("self")).unwrap();

    let mut cfg = hostile_cfg();
    cfg.scanner.follow_symlinks = true;

    let _diags = with_time_budget(Duration::from_secs(10), "symlink loop follow=true", || {
        scan_no_index(root, &cfg).expect("scan of cyclic symlink tree must not error")
    });
}

/// Same fixture with `follow_symlinks = false` must also terminate in
/// bounded time, the symlink is not followed, so the loop never expands,
/// but we pin the contract so flipping the default cannot introduce a hang
/// regression.
#[cfg(unix)]
#[test]
fn symlink_loop_does_not_hang_without_follow() {
    use nyx_scanner::scan_no_index;
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    std::fs::write(root.join("real.js"), b"var x = 1;\n").unwrap();
    let a = root.join("a");
    std::fs::create_dir(&a).unwrap();
    std::fs::write(a.join("inside.js"), b"var y = 2;\n").unwrap();
    symlink("../a", a.join("self")).unwrap();

    let mut cfg = hostile_cfg();
    cfg.scanner.follow_symlinks = false;

    let _diags = with_time_budget(Duration::from_secs(10), "symlink loop follow=false", || {
        scan_no_index(root, &cfg).expect("scan must not error on cyclic symlink with follow=false")
    });
}

/// Mutually-referencing symlinks (`dirA/link -> ../dirB`, `dirB/link -> ../dirA`)
/// are the second common loop shape.  Like the self-loop, this must terminate.
#[cfg(unix)]
#[test]
fn mutual_symlink_loop_does_not_hang() {
    use nyx_scanner::scan_no_index;
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    std::fs::write(root.join("real.js"), b"var x = 1;\n").unwrap();

    let dir_a = root.join("dirA");
    let dir_b = root.join("dirB");
    std::fs::create_dir(&dir_a).unwrap();
    std::fs::create_dir(&dir_b).unwrap();
    std::fs::write(dir_a.join("a.js"), b"var a = 1;\n").unwrap();
    std::fs::write(dir_b.join("b.js"), b"var b = 2;\n").unwrap();
    symlink("../dirB", dir_a.join("to_b")).unwrap();
    symlink("../dirA", dir_b.join("to_a")).unwrap();

    let mut cfg = hostile_cfg();
    cfg.scanner.follow_symlinks = true;

    let _diags = with_time_budget(Duration::from_secs(10), "mutual symlink loop", || {
        scan_no_index(root, &cfg).expect("scan must terminate on mutual symlink cycle")
    });
}
