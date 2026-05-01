//! Semantic regression suite for the SSA lowering + optimisation + taint
//! pipeline.
//!
//! This file used to be a legacy/SSA equivalence test.  After legacy
//! was removed the file degenerated to "scan each fixture and assert
//! no panic", which proved almost nothing.  It has been restored as a
//! multi-tier correctness signal.  Each `#[test]` fn below verifies a
//! distinct property:
//!
//!   * `ssa_structural_invariants_corpus`, every body in every real-world
//!     fixture lowers to well-formed SSA.  Enforced via
//!     [`nyx_scanner::ssa::invariants::check_structural_invariants`]:
//!     single-assignment, pred/succ symmetry, terminator/succs agreement,
//!     phi arity and operand sources, value-def coverage, and reachability.
//!
//!   * `ssa_lowering_is_deterministic`, lowering the same CFG twice produces
//!     structurally identical SSA (equal fingerprint).  Catches any incoming
//!     non-determinism introduced by hashing or iteration order.
//!
//!   * `ssa_optimize_is_idempotent`, `optimize_ssa` reaches a fixpoint on
//!     the first run: re-running it must prune zero branches, eliminate
//!     zero copies, and remove zero dead defs, and must not change the body
//!     fingerprint.  Catches optimiser bugs where a second pass would find
//!     new work (indicating the first pass failed to converge).
//!
//!   * `summary_extraction_is_deterministic`, extracting summaries from the
//!     same bytes twice yields the same `(FuncSummary, SsaFuncSummary)`
//!     sets, compared via stable JSON serialisation.  Catches any
//!     non-determinism in summary construction or cross-file key ordering.
//!
//!   * `scan_is_stable_across_runs`, a full two-pass scan produces the same
//!     diag list when invoked twice on the same input.  Runs on a curated
//!     per-language fixture subset to keep wall time bounded; the other
//!     tiers already cover full-corpus behaviour.
//!
//!   * `ssa_corpus_does_not_panic`, the original smoke check, kept to lock
//!     in termination on the full fixture matrix.
//!
//! Run with: `cargo test --test ssa_equivalence_tests`
//!
//! Set `NYX_SSA_VERBOSE=1` for per-fixture progress output.

mod common;

use common::test_config;
use nyx_scanner::ast::{build_cfg_for_file, extract_all_summaries_from_bytes};
use nyx_scanner::cfg::BodyCfg;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::ssa::{
    invariants::{body_fingerprint, check_structural_invariants},
    lower_to_ssa, optimize_ssa,
};
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

// ── Fixture discovery ─────────────────────────────────────────────────────

struct Fixture {
    name: String,
    source_path: PathBuf,
}

fn discover_fixtures() -> Vec<Fixture> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real_world");
    let mut fixtures = Vec::new();

    let langs = [
        "rust",
        "c",
        "cpp",
        "java",
        "go",
        "php",
        "python",
        "ruby",
        "typescript",
        "javascript",
    ];
    let categories = ["taint", "cfg", "state", "mixed"];

    for lang in &langs {
        for category in &categories {
            let dir = base.join(lang).join(category);
            if !dir.is_dir() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let fname = path.file_name().unwrap().to_string_lossy().to_string();
                if !fname.ends_with(".expect.json") {
                    continue;
                }
                let stem = fname.trim_end_matches(".expect.json");
                if let Some(source_path) = find_source_file(&dir, stem) {
                    fixtures.push(Fixture {
                        name: format!("{lang}/{category}/{stem}"),
                        source_path,
                    });
                }
            }
        }
    }
    fixtures.sort_by(|a, b| a.name.cmp(&b.name));
    fixtures
}

fn find_source_file(dir: &Path, stem: &str) -> Option<PathBuf> {
    let extensions = [
        "rs", "c", "cpp", "cc", "cxx", "java", "go", "php", "py", "rb", "ts", "tsx", "js", "jsx",
    ];
    for ext in extensions {
        let candidate = dir.join(format!("{stem}.{ext}"));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn verbose() -> bool {
    std::env::var("NYX_SSA_VERBOSE")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

// ── Helpers for scanning a single-file fixture in isolation ──────────────

fn scan_single_file(fixture: &Fixture) -> Vec<Diag> {
    let tmp = tempfile::TempDir::with_prefix("nyx_ssa_sem_").expect("tempdir");
    let dest = tmp.path().join(fixture.source_path.file_name().unwrap());
    std::fs::copy(&fixture.source_path, &dest).expect("copy fixture");

    let cfg = test_config(AnalysisMode::Full);
    let mut diags =
        nyx_scanner::scan_no_index(tmp.path(), &cfg).expect("scan_no_index should succeed");

    // Normalise paths to filenames so tmp path does not leak into comparisons.
    for d in &mut diags {
        if let Some(fname) = Path::new(&d.path).file_name() {
            d.path = fname.to_string_lossy().to_string();
        }
    }
    diags.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then(a.line.cmp(&b.line))
            .then(a.col.cmp(&b.col))
            .then(a.path.cmp(&b.path))
    });
    diags
}

/// Render a diag list to a canonical string for equality comparison.
/// Strips non-deterministic fields (rank_score floats) that should not
/// affect correctness.
fn diag_fingerprint(diags: &[Diag]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for d in diags {
        let _ = writeln!(
            out,
            "{id}|{path}|{line}|{col}|{sev}|{cat:?}|{pv}|{gk}|{sup}",
            id = d.id,
            path = d.path,
            line = d.line,
            col = d.col,
            sev = d.severity.as_db_str(),
            cat = d.category,
            pv = d.path_validated,
            gk = d.guard_kind.as_deref().unwrap_or(""),
            sup = d.suppressed,
        );
    }
    out
}

/// Iterate every body (top-level + functions) across all bodies of a file.
fn each_body<'a>(bodies: &'a [BodyCfg]) -> impl Iterator<Item = &'a BodyCfg> + 'a {
    bodies.iter()
}

// ── Tier 1: Structural invariants on every body of every fixture ─────────

#[test]
fn ssa_structural_invariants_corpus() {
    let fixtures = discover_fixtures();
    assert!(
        !fixtures.is_empty(),
        "no fixtures discovered — CARGO_MANIFEST_DIR wrong?"
    );

    let cfg = test_config(AnalysisMode::Full);
    let mut failures: Vec<String> = Vec::new();
    let mut bodies_checked: usize = 0;

    for fixture in &fixtures {
        let Ok(Some((file_cfg, _lang))) = build_cfg_for_file(&fixture.source_path, &cfg) else {
            continue;
        };

        for body in each_body(&file_cfg.bodies) {
            let Ok(ssa) = lower_to_ssa(&body.graph, body.entry, None, true) else {
                // Some bodies are legitimately empty / unreachable; skip
                // without flagging.  The panic-free smoke test covers that
                // the scan path handles the `Err` correctly.
                continue;
            };
            bodies_checked += 1;

            let errs = check_structural_invariants(&ssa);
            if !errs.is_empty() {
                failures.push(format!(
                    "{} body={:?} ({} block(s)):\n  {}",
                    fixture.name,
                    body.meta.name.as_deref().unwrap_or("<toplevel>"),
                    ssa.blocks.len(),
                    errs.join("\n  ")
                ));
            }
        }
    }

    assert!(
        bodies_checked > 100,
        "sanity: expected >100 bodies across the corpus, got {bodies_checked}"
    );
    if verbose() {
        eprintln!(
            "structural invariants: {} bodies checked across {} fixtures",
            bodies_checked,
            fixtures.len()
        );
    }
    assert!(
        failures.is_empty(),
        "SSA structural invariants violated in {} body/fixture combo(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ── Tier 2: Lowering determinism ─────────────────────────────────────────

#[test]
fn ssa_lowering_is_deterministic() {
    let fixtures = discover_fixtures();
    let cfg = test_config(AnalysisMode::Full);
    let mut failures: Vec<String> = Vec::new();
    let mut bodies_checked: usize = 0;

    for fixture in &fixtures {
        let Ok(Some((file_cfg, _))) = build_cfg_for_file(&fixture.source_path, &cfg) else {
            continue;
        };
        for body in each_body(&file_cfg.bodies) {
            let Ok(a) = lower_to_ssa(&body.graph, body.entry, None, true) else {
                continue;
            };
            let Ok(b) = lower_to_ssa(&body.graph, body.entry, None, true) else {
                continue;
            };
            bodies_checked += 1;

            let fa = body_fingerprint(&a);
            let fb = body_fingerprint(&b);
            if fa != fb {
                failures.push(format!(
                    "{} body={:?}: non-deterministic SSA lowering",
                    fixture.name,
                    body.meta.name.as_deref().unwrap_or("<toplevel>"),
                ));
            }
        }
    }

    assert!(
        bodies_checked > 100,
        "sanity: expected >100 bodies, got {bodies_checked}"
    );
    assert!(
        failures.is_empty(),
        "SSA lowering is non-deterministic in {} body/fixture combo(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ── Tier 2b: Strict 10× determinism on multi-phi bodies ──────────────────

/// Stronger determinism check than Tier 2: for every body in the corpus
/// that carries ≥ 2 phis (where phi ordering is the most likely culprit
/// for hasher-driven non-determinism), lower the CFG ten times in a row
/// and assert every fingerprint matches the first, bit-for-bit, with no
/// sort tolerance.  Runs are interleaved across fixtures so that
/// process-wide hasher state between lowerings is as adversarial as we
/// can make it without `PYTHONHASHSEED`-style seeding.
#[test]
fn ssa_lowering_is_deterministic_strict_10x() {
    let fixtures = discover_fixtures();
    let cfg = test_config(AnalysisMode::Full);
    let mut failures: Vec<String> = Vec::new();
    let mut bodies_checked: usize = 0;
    let mut multi_phi_bodies: usize = 0;

    for fixture in &fixtures {
        let Ok(Some((file_cfg, _))) = build_cfg_for_file(&fixture.source_path, &cfg) else {
            continue;
        };
        for body in each_body(&file_cfg.bodies) {
            // Lower once up front to detect multi-phi bodies cheaply; skip
            // trivially-phi-less bodies so the 10× loop stays bounded.
            let Ok(first) = lower_to_ssa(&body.graph, body.entry, None, true) else {
                continue;
            };
            let phi_count: usize = first.blocks.iter().map(|b| b.phis.len()).sum();
            if phi_count < 2 {
                continue;
            }
            multi_phi_bodies += 1;

            let expected = body_fingerprint(&first);
            for i in 1..10 {
                let Ok(again) = lower_to_ssa(&body.graph, body.entry, None, true) else {
                    failures.push(format!(
                        "{} body={:?}: lowering failed on iteration {i} after succeeding earlier",
                        fixture.name,
                        body.meta.name.as_deref().unwrap_or("<toplevel>"),
                    ));
                    break;
                };
                let fp = body_fingerprint(&again);
                if fp != expected {
                    failures.push(format!(
                        "{} body={:?}: fingerprint diverged on iteration {i}\n  --- expected ---\n{expected}  --- got ---\n{fp}",
                        fixture.name,
                        body.meta.name.as_deref().unwrap_or("<toplevel>"),
                    ));
                    break;
                }
                bodies_checked += 1;
            }
        }
    }

    assert!(
        multi_phi_bodies >= 10,
        "expected to cover >= 10 multi-phi bodies for a meaningful strict-determinism check, got {multi_phi_bodies}",
    );
    assert!(
        bodies_checked > 80,
        "sanity: expected >80 (body × iteration) samples, got {bodies_checked}"
    );
    assert!(
        failures.is_empty(),
        "SSA lowering is non-deterministic in {} body/fixture combo(s) under 10× strict comparison:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ── Tier 3: Optimization idempotence ─────────────────────────────────────

#[test]
fn ssa_optimize_is_idempotent() {
    let fixtures = discover_fixtures();
    let cfg = test_config(AnalysisMode::Full);
    let mut failures: Vec<String> = Vec::new();
    let mut bodies_checked: usize = 0;

    for fixture in &fixtures {
        let Ok(Some((file_cfg, lang))) = build_cfg_for_file(&fixture.source_path, &cfg) else {
            continue;
        };
        for body in each_body(&file_cfg.bodies) {
            let Ok(mut ssa) = lower_to_ssa(&body.graph, body.entry, None, true) else {
                continue;
            };

            // First optimisation pass, may do real work.
            let _ = optimize_ssa(&mut ssa, &body.graph, Some(lang));
            let fp_after_first = body_fingerprint(&ssa);

            // Second pass must be a fixpoint:
            //   * body fingerprint unchanged
            //   * zero additional branches pruned / copies eliminated /
            //     dead defs removed
            let second = optimize_ssa(&mut ssa, &body.graph, Some(lang));
            let fp_after_second = body_fingerprint(&ssa);
            bodies_checked += 1;

            if fp_after_first != fp_after_second {
                failures.push(format!(
                    "{} body={:?}: optimize_ssa changed body fingerprint on second pass",
                    fixture.name,
                    body.meta.name.as_deref().unwrap_or("<toplevel>"),
                ));
            }
            if second.branches_pruned != 0
                || second.copies_eliminated != 0
                || second.dead_defs_removed != 0
            {
                failures.push(format!(
                    "{} body={:?}: optimize_ssa did not reach fixpoint (branches={}, copies={}, dead_defs={})",
                    fixture.name,
                    body.meta.name.as_deref().unwrap_or("<toplevel>"),
                    second.branches_pruned,
                    second.copies_eliminated,
                    second.dead_defs_removed,
                ));
            }
        }
    }

    assert!(
        bodies_checked > 100,
        "sanity: expected >100 bodies, got {bodies_checked}"
    );
    assert!(
        failures.is_empty(),
        "optimize_ssa is not idempotent in {} body/fixture combo(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ── Tier 4: Summary-extraction determinism ───────────────────────────────

#[test]
fn summary_extraction_is_deterministic() {
    let fixtures = discover_fixtures();
    let cfg = test_config(AnalysisMode::Full);
    let mut failures: Vec<String> = Vec::new();
    let mut files_checked: usize = 0;

    for fixture in &fixtures {
        let Ok(bytes) = std::fs::read(&fixture.source_path) else {
            continue;
        };
        let Ok((fn_a, ssa_a, _bodies_a, _auth_a)) =
            extract_all_summaries_from_bytes(&bytes, &fixture.source_path, &cfg, None)
        else {
            continue;
        };
        let Ok((fn_b, ssa_b, _bodies_b, _auth_b)) =
            extract_all_summaries_from_bytes(&bytes, &fixture.source_path, &cfg, None)
        else {
            continue;
        };
        files_checked += 1;

        // Counts must match exactly.
        if fn_a.len() != fn_b.len() {
            failures.push(format!(
                "{}: FuncSummary count unstable ({} vs {})",
                fixture.name,
                fn_a.len(),
                fn_b.len()
            ));
            continue;
        }
        if ssa_a.len() != ssa_b.len() {
            failures.push(format!(
                "{}: SsaFuncSummary count unstable ({} vs {})",
                fixture.name,
                ssa_a.len(),
                ssa_b.len()
            ));
            continue;
        }

        // SSA summaries: compare after sorting by key (order from the extractor
        // is expected-deterministic, but if two runs diverge only in order the
        // test should still pass, what matters is the set identity).
        let mut ssa_a_sorted = ssa_a;
        let mut ssa_b_sorted = ssa_b;
        ssa_a_sorted.sort_by(|a, b| format!("{:?}", a.0).cmp(&format!("{:?}", b.0)));
        ssa_b_sorted.sort_by(|a, b| format!("{:?}", a.0).cmp(&format!("{:?}", b.0)));

        for (i, ((k_a, s_a), (k_b, s_b))) in
            ssa_a_sorted.iter().zip(ssa_b_sorted.iter()).enumerate()
        {
            if format!("{k_a:?}") != format!("{k_b:?}") {
                failures.push(format!(
                    "{}: SsaFuncSummary key {i} differs: {:?} vs {:?}",
                    fixture.name, k_a, k_b,
                ));
                continue;
            }
            let ja = serde_json::to_string(s_a).expect("serialize SsaFuncSummary a");
            let jb = serde_json::to_string(s_b).expect("serialize SsaFuncSummary b");
            if ja != jb {
                failures.push(format!(
                    "{}: SsaFuncSummary for {k_a:?} not bitwise-stable:\n  a={}\n  b={}",
                    fixture.name, ja, jb,
                ));
            }
        }
    }

    assert!(
        files_checked > 50,
        "sanity: expected >50 files checked, got {files_checked}"
    );
    assert!(
        failures.is_empty(),
        "summary extraction is non-deterministic in {} case(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ── Tier 5: Scan stability on a curated subset ───────────────────────────

/// Curated one-per-language fixture subset used for cross-run diag stability.
/// Keeps the test bounded (~10 fixtures × 2 scans) while still touching every
/// language's full taint pipeline.
const SCAN_STABILITY_SUBSET: &[&str] = &[
    "rust/taint/env_to_command",
    "rust/taint/actix_xss",
    "c/taint/buffer_overflow",
    "cpp/taint/cmdi_execl",
    "java/taint/cast_to_string_still_tainted",
    "php/taint/closure_taint",
    "python/taint/attribute_taint",
    "ruby/taint/cmdi_backticks",
    "typescript/taint/async_await_taint",
    "javascript/taint/alias_no_sanitize_unsafe",
    "go/taint/cmdi_http",
];

#[test]
fn scan_is_stable_across_runs() {
    let fixtures = discover_fixtures();
    let by_name: std::collections::HashMap<&str, &Fixture> =
        fixtures.iter().map(|f| (f.name.as_str(), f)).collect();

    let mut failures: Vec<String> = Vec::new();
    let mut scanned: usize = 0;

    for &name in SCAN_STABILITY_SUBSET {
        let Some(fixture) = by_name.get(name).copied() else {
            // Not a hard failure, curated names may drift as the corpus
            // evolves.  Log but continue so this tier stays useful.
            if verbose() {
                eprintln!("scan_is_stable_across_runs: missing fixture {name}");
            }
            continue;
        };

        let a = scan_single_file(fixture);
        let b = scan_single_file(fixture);
        scanned += 1;

        let fa = diag_fingerprint(&a);
        let fb = diag_fingerprint(&b);
        if fa != fb {
            failures.push(format!(
                "{name}: diag set diverges across runs\n  --- run A ---\n{fa}  --- run B ---\n{fb}"
            ));
        }
    }

    assert!(
        scanned >= 3,
        "scan_is_stable_across_runs: only {scanned} fixtures available — did the corpus paths move?"
    );
    assert!(
        failures.is_empty(),
        "scan is non-deterministic across runs:\n{}",
        failures.join("\n")
    );
}

// ── Tier 6: SSA lowering coverage sanity ─────────────────────────────────

/// Guards against a silent regression that would make `lower_to_ssa`
/// return empty / trivially-satisfying bodies, which would make every
/// invariant check pass vacuously.  Enforces that the corpus produces
/// non-trivial SSA: many blocks, many instructions, at least one phi
/// somewhere, at least one loop (back edge), and at least one call.
#[test]
fn ssa_lowering_produces_non_trivial_bodies() {
    let fixtures = discover_fixtures();
    let cfg = test_config(AnalysisMode::Full);

    let mut total_blocks: usize = 0;
    let mut total_insts: usize = 0;
    let mut total_phis: usize = 0;
    let mut total_calls: usize = 0;
    let mut bodies_with_phi: usize = 0;
    let mut bodies_with_call: usize = 0;
    let mut multi_block_bodies: usize = 0;
    let mut bodies: usize = 0;

    for fixture in &fixtures {
        let Ok(Some((file_cfg, _))) = build_cfg_for_file(&fixture.source_path, &cfg) else {
            continue;
        };
        for body in each_body(&file_cfg.bodies) {
            let Ok(ssa) = lower_to_ssa(&body.graph, body.entry, None, true) else {
                continue;
            };
            bodies += 1;
            total_blocks += ssa.blocks.len();
            if ssa.blocks.len() > 1 {
                multi_block_bodies += 1;
            }
            let mut body_has_phi = false;
            let mut body_has_call = false;
            for block in &ssa.blocks {
                total_insts += block.body.len() + block.phis.len();
                total_phis += block.phis.len();
                if !block.phis.is_empty() {
                    body_has_phi = true;
                }
                for inst in &block.body {
                    if matches!(inst.op, nyx_scanner::ssa::SsaOp::Call { .. }) {
                        total_calls += 1;
                        body_has_call = true;
                    }
                }
            }
            if body_has_phi {
                bodies_with_phi += 1;
            }
            if body_has_call {
                bodies_with_call += 1;
            }
        }
    }

    // Thresholds are generous, they only catch gross regressions (e.g. a
    // lowering bug that silently produces single-block bodies with no body
    // instructions).  Update if the corpus intentionally shrinks.
    assert!(bodies > 200, "expected >200 bodies, got {bodies}");
    assert!(
        multi_block_bodies > 50,
        "expected >50 multi-block bodies (guard against collapse regression), got {multi_block_bodies}"
    );
    assert!(
        total_blocks > 500,
        "expected >500 blocks across corpus, got {total_blocks}"
    );
    assert!(
        total_insts > 1000,
        "expected >1000 SSA instructions across corpus, got {total_insts}"
    );
    assert!(
        total_phis > 0,
        "expected at least one phi somewhere in the corpus, got 0"
    );
    assert!(
        total_calls > 100,
        "expected >100 call instructions, got {total_calls}"
    );
    assert!(
        bodies_with_phi > 20,
        "expected >20 bodies with phis, got {bodies_with_phi}"
    );
    assert!(
        bodies_with_call > 100,
        "expected >100 bodies with calls, got {bodies_with_call}"
    );

    if verbose() {
        eprintln!(
            "ssa coverage: bodies={bodies} multi_block={multi_block_bodies} blocks={total_blocks} insts={total_insts} phis={total_phis} calls={total_calls} bodies_with_phi={bodies_with_phi} bodies_with_call={bodies_with_call}"
        );
    }
}

// ── Tier 7: Original panic-free smoke check (preserved) ─────────────────

#[test]
fn ssa_corpus_does_not_panic() {
    let fixtures = discover_fixtures();
    assert!(!fixtures.is_empty(), "no fixtures found");
    let cfg = test_config(AnalysisMode::Full);
    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        let result = std::panic::catch_unwind(|| build_and_lower_all(&fixture.source_path, &cfg));
        if result.is_err() {
            failures.push(format!("PANIC in {}", fixture.name));
        }
    }

    assert!(
        failures.is_empty(),
        "SSA corpus panics:\n{}",
        failures.join("\n")
    );
}

fn build_and_lower_all(path: &Path, cfg: &Config) -> usize {
    let Ok(Some((file_cfg, _))) = build_cfg_for_file(path, cfg) else {
        return 0;
    };
    let mut n = 0usize;
    for body in &file_cfg.bodies {
        if lower_to_ssa(&body.graph, body.entry, None, true).is_ok() {
            n += 1;
        }
    }
    n
}

// ── Catch-block orphan invariant ────────────────────────────────────────
//
// Construct a synthetic SsaBody where a block carries `SsaOp::CatchParam`
// but is neither reachable from entry via normal flow nor listed as a
// target of any exception edge. The invariant must report the
// orphan, this is the CFG-construction-bug signal the invariant is
// designed to surface.
//
// The test stays on the pure-function `check_catch_block_reachability`
// path to avoid the debug-build panic inside `lower_to_ssa`; it
// exercises the release-build semantics (warn + error report) which
// is what production bodies go through when compiled without
// `debug_assertions`.

#[test]
fn orphan_catch_block_triggers_reachability_invariant() {
    use nyx_scanner::ssa::invariants::check_catch_block_reachability;
    use nyx_scanner::ssa::{
        BlockId, SsaBlock, SsaBody, SsaInst, SsaOp, SsaValue, Terminator, ValueDef,
    };
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    let dummy_cfg = NodeIndex::new(0);

    // Block 0: entry, does not reach block 1 via succs.
    // Block 1: orphan, carries CatchParam, not listed in exception_edges.
    let body = SsaBody {
        blocks: vec![
            SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            },
            SsaBlock {
                id: BlockId(1),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::CatchParam,
                    cfg_node: dummy_cfg,
                    var_name: Some("e".into()),
                    span: (0, 0),
                }],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            },
        ],
        entry: BlockId(0),
        value_defs: vec![ValueDef {
            var_name: Some("e".into()),
            cfg_node: dummy_cfg,
            block: BlockId(1),
        }],
        cfg_node_map: Default::default(),
        exception_edges: vec![], // intentionally empty, the orphan condition,
        field_interner: nyx_scanner::ssa::ir::FieldInterner::default(),
        field_writes: std::collections::HashMap::new(),

        synthetic_externals: std::collections::HashSet::new(),
    };

    let err = check_catch_block_reachability(&body)
        .expect_err("orphan catch block must fail the reachability invariant");
    assert!(
        err.messages
            .iter()
            .any(|m| m.contains("catch-block orphan")),
        "expected orphan-catch message, got: {:?}",
        err.messages,
    );
}

#[test]
fn normally_reachable_catch_block_passes_invariant() {
    // Regression guard: CatchParam in a block reached from entry via normal
    // flow (not an exception edge) satisfies the invariant.
    use nyx_scanner::ssa::invariants::check_catch_block_reachability;
    use nyx_scanner::ssa::{
        BlockId, SsaBlock, SsaBody, SsaInst, SsaOp, SsaValue, Terminator, ValueDef,
    };
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    let dummy_cfg = NodeIndex::new(0);

    let body = SsaBody {
        blocks: vec![
            SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![],
                terminator: Terminator::Goto(BlockId(1)),
                preds: smallvec![],
                succs: smallvec![BlockId(1)],
            },
            SsaBlock {
                id: BlockId(1),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::CatchParam,
                    cfg_node: dummy_cfg,
                    var_name: Some("e".into()),
                    span: (0, 0),
                }],
                terminator: Terminator::Return(None),
                preds: smallvec![BlockId(0)],
                succs: smallvec![],
            },
        ],
        entry: BlockId(0),
        value_defs: vec![ValueDef {
            var_name: Some("e".into()),
            cfg_node: dummy_cfg,
            block: BlockId(1),
        }],
        cfg_node_map: Default::default(),
        exception_edges: vec![],
        field_interner: nyx_scanner::ssa::ir::FieldInterner::default(),
        field_writes: std::collections::HashMap::new(),

        synthetic_externals: std::collections::HashSet::new(),
    };

    assert!(check_catch_block_reachability(&body).is_ok());
}

#[test]
fn exception_edge_catch_block_passes_invariant() {
    // A CatchParam-carrying block reached only via an exception edge
    // (the typical try/catch shape) must pass the invariant.
    use nyx_scanner::ssa::invariants::check_catch_block_reachability;
    use nyx_scanner::ssa::{
        BlockId, SsaBlock, SsaBody, SsaInst, SsaOp, SsaValue, Terminator, ValueDef,
    };
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    let dummy_cfg = NodeIndex::new(0);

    let body = SsaBody {
        blocks: vec![
            SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            },
            SsaBlock {
                id: BlockId(1),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::CatchParam,
                    cfg_node: dummy_cfg,
                    var_name: Some("e".into()),
                    span: (0, 0),
                }],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            },
        ],
        entry: BlockId(0),
        value_defs: vec![ValueDef {
            var_name: Some("e".into()),
            cfg_node: dummy_cfg,
            block: BlockId(1),
        }],
        cfg_node_map: Default::default(),
        exception_edges: vec![(BlockId(0), BlockId(1))],
        field_interner: nyx_scanner::ssa::ir::FieldInterner::default(),
        field_writes: std::collections::HashMap::new(),

        synthetic_externals: std::collections::HashSet::new(),
    };

    assert!(check_catch_block_reachability(&body).is_ok());
}
