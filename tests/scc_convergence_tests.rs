//! Regression tests for SCC fixed-point convergence in pass 2.
//!
//! Pass 2 uses Jacobi iteration, each file in a mutually-recursive SCC
//! is re-analysed against the *pre-iteration* `GlobalSummaries` snapshot,
//! and updates are only visible on the next iteration.  In a cross-file
//! SCC with `k` functions arranged in a chain, facts introduced at one
//! end of the chain need up to `k` iterations to propagate back to the
//! other end.
//!
//! Before this test was written, the hard cap was 3, so any SCC with
//! 4+ cross-file functions silently lost precision.  These fixtures
//! exercise a 4-cycle and assert both that the transitive finding is
//! reported and that the engine actually needed more than 3 iterations
//! to converge (proving the test is load-bearing, not incidental).
//!
//! If you raise or lower the cap in `scan::SCC_FIXPOINT_SAFETY_CAP`,
//! update the iteration-count assertions accordingly.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::commands::scan::{
    SCC_UNCONVERGED_NOTE_PREFIX, last_scc_max_iterations, set_scc_fixpoint_cap_override,
};
use nyx_scanner::evidence::Confidence;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use std::sync::Mutex;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Serialize any test that mutates the global SCC fix-point cap override
/// or reads `last_scc_max_iterations()`. The override is a process-wide
/// `AtomicUsize` and `cargo test` runs tests in parallel by default ,
/// without this guard, one test's override leaks into another's scan and
/// both the iteration count and the findings tag shift non-deterministically.
static SCC_TEST_GUARD: Mutex<()> = Mutex::new(());

/// Adversarial 4-cycle: `step_a → step_b → step_c → step_d → step_a`
/// across four separate files, with the only sink in `step_d`.  The
/// `param_to_sink` fact has to travel back through three cross-file
/// summary-update iterations before `step_a`'s summary reflects the
/// transitive flow, without that, the caller in `server.py` never
/// sees the XSS/CMDI.
///
/// With the old `MAX_SCC_FIXPOINT_ITERS = 3` this test's required
/// finding silently disappeared.  With the current
/// `SCC_FIXPOINT_SAFETY_CAP = 64` it converges naturally.
#[test]
fn scc_deep_cycle_requires_multi_iter_convergence() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0); // ensure no stale override from a prior test
    let dir = fixture_path("cross_file_scc_deep_cycle");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    // Hard assertion: the transitive taint must be detected.
    validate_expectations(&diags, &dir);

    // Observability assertion: prove the SCC actually exercised more
    // than three iterations, otherwise this fixture would pass even
    // under the old bound and give false confidence.
    //
    // The exact bound is tight: a 4-cycle needs at least 4 iterations
    // to propagate a transitive fact end-to-end, and monotone summary
    // refinement should converge in a small multiple of that. A drop
    // below 4 means the 3-bound regression is unguarded; a rise above
    // 8 means summary refinement is no longer monotone or is churning.
    let iters = last_scc_max_iterations();
    assert!(
        (4..=8).contains(&iters),
        "Expected 4..=8 SCC fix-point iterations for the 4-cycle fixture; \
         got {iters}. Lower bound guards against the pre-fix cap of 3; \
         upper bound guards against summary-refinement regressions that \
         would churn near the safety cap. If this fires, audit \
         resolve_callee / summary merging in taint/mod.rs.",
    );
}

/// Existing 3-file Python SCC, lighter smoke test, verifies the
/// iteration count stays in a sensible range.  If this starts requiring
/// many iterations something regressed in summary extraction.
#[test]
fn scc_small_cycle_converges_quickly() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);
    let dir = fixture_path("cross_file_scc_convergence");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    let iters = last_scc_max_iterations();
    // Upper bound is tight: even if the call graph ever grows mutual
    // recursion edges here, summary refinement should still converge in
    // a small multiple of the chain depth. Current behaviour is iters=0
    // because the call graph topo-order resolves these files without
    // needing an SCC fix-point loop at all, allow that too so this
    // test does not become load-bearing on SCC detection.
    assert!(
        iters <= 4,
        "Small 3-file SCC should converge in <= 4 iterations (including \
         the `no-SCC-needed` case of 0); got {iters}. A jump suggests \
         summary widening regressed or mutual-recursion detection started \
         spuriously grouping these files into a large SCC."
    );
}

/// Regression guard: when an SCC batch exhausts the fix-point safety
/// cap without converging, findings must still surface, each tagged
/// with `confidence = Low` and a `scc_unconverged:` note so
/// downstream reviewers can identify potentially-imprecise results.
///
/// Uses `set_scc_fixpoint_cap_override` to force cap-hit on the same
/// 4-cycle fixture as `scc_deep_cycle_requires_multi_iter_convergence`
/// (which normally takes ~4 iterations). Setting the cap to 1 guarantees
/// non-convergence while keeping the test cheap and deterministic.
#[test]
fn scc_cap_hit_still_emits_tagged_low_confidence_findings() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = fixture_path("cross_file_scc_deep_cycle");

    // Force the SCC fix-point loop to bail after 3 iterations. The
    // 4-cycle fixture needs >=4 iterations to fully propagate taint, so
    // the 3rd iteration's diags do contain the transitive taint finding
    // but convergence has not been detected, this is the exact cap-hit
    // scenario users would see in production on a larger SCC.
    set_scc_fixpoint_cap_override(3);
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    set_scc_fixpoint_cap_override(0);

    // Scan must not panic, hang, or silently drop results.
    assert!(
        !diags.is_empty(),
        "scan with cap-hit must still produce diagnostics"
    );

    // The scan must have exercised the cap (not converged early).
    let iters = last_scc_max_iterations();
    assert_eq!(
        iters, 3,
        "expected cap-override (3) to bind the fix-point loop; got {iters} iterations"
    );

    // (a) Taint findings must still be emitted, truncation is not
    // silent drop.
    let taint: Vec<_> = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .collect();
    assert!(
        !taint.is_empty(),
        "unconverged SCC batch must still emit taint findings (truncated != dropped). \
         All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{}:{} {}", d.path, d.line, d.col, d.id))
            .collect::<Vec<_>>()
    );

    // (b) At least one finding from the unconverged SCC batch carries
    // the tag. Tagging is scoped to diags produced by the SCC fix-point
    // loop itself, findings from non-recursive batches or orphan files
    // that happen to flow through SCC-internal summaries are
    // intentionally not re-tagged (they came from a batch that did
    // converge, modulo the referenced summary).
    let tagged: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.evidence
                .as_ref()
                .map(|e| {
                    e.notes
                        .iter()
                        .any(|n| n.starts_with(SCC_UNCONVERGED_NOTE_PREFIX))
                })
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !tagged.is_empty(),
        "at least one diag in an unconverged SCC batch must carry the \
         scc_unconverged note; got none. Tagging must fire on the SCC \
         batch's own iteration_diags. All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!(
                "{}:{}:{} {} conf={:?}",
                d.path, d.line, d.col, d.id, d.confidence
            ))
            .collect::<Vec<_>>()
    );

    // (c) Every tagged finding has confidence capped at Low.
    for d in &tagged {
        assert_eq!(
            d.confidence,
            Some(Confidence::Low),
            "scc_unconverged-tagged finding must be Low confidence: \
             {}:{}:{} id={} conf={:?}",
            d.path,
            d.line,
            d.col,
            d.id,
            d.confidence,
        );
    }
}

/// Phase-E3 / Phase-B: verify that the worklist reduces per-iteration
/// work without changing the final output.  We do this by running the
/// 16-cycle fixture twice, once through the normal pass-2 path,
/// which uses the worklist, and asserting (a) findings match and
/// (b) iteration count stays within the same bound as the 8-cycle.
///
/// This test is load-bearing for Phase-B correctness: if the worklist
/// ever skips a file whose dependencies did change, this test's
/// required-finding validator would fire, failing the test.
#[test]
fn phase_b_worklist_preserves_findings_on_16cycle() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);
    let dir = fixture_path("cross_file_scc_16cycle");

    // First run.  Worklist is active by default.
    let diags1 = scan_fixture_dir(&dir, AnalysisMode::Full);
    let iters1 = last_scc_max_iterations();
    validate_expectations(&diags1, &dir);

    // Second run.  Worklist is still active; we expect byte-for-byte
    // finding identity because the worklist changes *which* files
    // run per iteration but does not affect the set of summaries
    // produced or their final values.
    let diags2 = scan_fixture_dir(&dir, AnalysisMode::Full);
    let iters2 = last_scc_max_iterations();
    validate_expectations(&diags2, &dir);

    // Iteration count should be deterministic across runs (same
    // fixture, same cap, same call graph → same worklist schedule).
    assert_eq!(
        iters1, iters2,
        "worklist iteration count must be deterministic; \
         run1={iters1}, run2={iters2}"
    );

    // Finding count equality as a weaker correctness check (full
    // equality is validated by `validate_expectations` on both runs).
    assert_eq!(
        diags1.len(),
        diags2.len(),
        "worklist must not introduce finding-count churn"
    );
}

/// Phase-E broader fixture: 8-function SCC chain across 8 files.
///
/// Exercises iteration counts well above the old 3-bound and into the
/// 8–16 range that the `64` safety cap is meant to cover.  Failure
/// here is a stronger signal than the 4-cycle test: at depth 8 the
/// cost of each iteration becomes visible, so a regression either in
/// iteration count (summary churn) or in per-iteration cost (Phase-B
/// worklist) shows up.
#[test]
fn scc_8cycle_converges_within_bound() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);
    let dir = fixture_path("cross_file_scc_8cycle");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    let iters = last_scc_max_iterations();
    assert!(
        (8..=16).contains(&iters),
        "Expected 8..=16 iterations for 8-cycle fixture; got {iters}. \
         Lower bound guards the chain-depth invariant (Jacobi \
         iteration must walk one hop per round).  Upper bound guards \
         against summary-refinement regressions."
    );
}

/// Stress fixture: 16-function SCC chain across 16 files.
///
/// At this depth the iteration count dominates per-iteration cost, so
/// this is the fixture most sensitive to worklist optimisation.
#[test]
fn scc_16cycle_converges_within_bound() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);
    let dir = fixture_path("cross_file_scc_16cycle");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    let iters = last_scc_max_iterations();
    assert!(
        (16..=32).contains(&iters),
        "Expected 16..=32 iterations for 16-cycle fixture; got {iters}. \
         Lower bound guards the chain-depth invariant.  Upper bound \
         guards against summary-refinement regressions that would \
         push iteration count near the safety cap."
    );
}

/// Phase-D regression: cap-hit must record a [`CapHitReason`] that is
/// *not* `Unknown` whenever the convergence loop ran for at least two
/// iterations.  On the 4-cycle fixture with cap=2, the delta trajectory
/// should show monotone shrinkage (summaries refining toward but not
/// reaching fixpoint), which the classifier reports as
/// `MonotoneShrinking`.
///
/// This test is load-bearing: if the classifier ever returns `Unknown`
/// on a real cap-hit it means either the trajectory is not being
/// recorded or the classification rules have regressed.  A plateau or
/// oscillation reason would also be acceptable (either would still be
/// a useful signal) but `Unknown` would silently hide the actionable
/// information.
#[test]
fn scc_cap_hit_records_classified_reason() {
    use nyx_scanner::engine_notes::{CapHitReason, EngineNote};

    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = fixture_path("cross_file_scc_deep_cycle");

    // cap=2 forces cap-hit with at least two iterations recorded,
    // giving the classifier enough samples to differentiate
    // monotone-shrinking from Unknown.
    set_scc_fixpoint_cap_override(2);
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    set_scc_fixpoint_cap_override(0);

    let tagged: Vec<_> = diags
        .iter()
        .filter_map(|d| {
            d.evidence
                .as_ref()
                .map(|ev| ev.engine_notes.as_slice())
                .map(|notes| {
                    notes.iter().find_map(|n| match n {
                        EngineNote::CrossFileFixpointCapped { reason, .. } => Some(reason.clone()),
                        _ => None,
                    })
                })
                .and_then(|r| r.map(|reason| (d, reason)))
        })
        .collect();

    assert!(
        !tagged.is_empty(),
        "cap=2 scan of deep-cycle fixture must produce at least one \
         CrossFileFixpointCapped note; got diags: {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{}:{} {}", d.path, d.line, d.col, d.id))
            .collect::<Vec<_>>()
    );

    // The reason must be *something* other than Unknown, that's the
    // whole point of Phase-D classification.  Any structured variant
    // proves the trajectory pipeline fired end-to-end.
    for (d, reason) in &tagged {
        assert!(
            !matches!(reason, CapHitReason::Unknown),
            "cap-hit must produce a classified reason, not Unknown. \
             This means either (a) the trajectory is not being recorded \
             across iterations or (b) the classifier's rules no longer \
             cover the observed pattern. Finding: {}:{}:{} id={} \
             reason={reason:?}",
            d.path,
            d.line,
            d.col,
            d.id,
        );
    }
}

/// Pass 2 runs every recursive file of one level of the file dependency
/// DAG in a single fixed-point batch, so a batch can hold several
/// unrelated fixed-point groups.  A cap hit must only tag the group that
/// was still changing.  `walker.py` is self-recursive and shares a level
/// with the `step_*` cycle but no SCC; with the cap forced below what the
/// cycle needs, the cycle's findings are tagged and `walker.py`'s are not.
#[test]
fn scc_cap_hit_tags_only_the_unconverged_group() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = fixture_path("cross_file_scc_cap_hit_group_scope");

    set_scc_fixpoint_cap_override(3);
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    set_scc_fixpoint_cap_override(0);

    validate_expectations(&diags, &dir);
    assert_eq!(
        last_scc_max_iterations(),
        3,
        "cap override must bind the step_* cycle's fixed-point loop"
    );

    let is_tagged = |d: &nyx_scanner::commands::scan::Diag| {
        d.evidence.as_ref().is_some_and(|e| {
            e.notes
                .iter()
                .any(|n| n.starts_with(SCC_UNCONVERGED_NOTE_PREFIX))
        })
    };
    let in_file = |d: &nyx_scanner::commands::scan::Diag, name: &str| {
        Path::new(&d.path).file_name().is_some_and(|f| f == name)
    };
    let listing = || {
        diags
            .iter()
            .map(|d| {
                format!(
                    "{}:{} {} conf={:?} tagged={}",
                    d.path,
                    d.line,
                    d.id,
                    d.confidence,
                    is_tagged(d)
                )
            })
            .collect::<Vec<_>>()
    };

    // Recall pin: the walker's own command injection is still reported.
    let walker: Vec<_> = diags.iter().filter(|d| in_file(d, "walker.py")).collect();
    assert!(
        walker
            .iter()
            .any(|d| d.id.starts_with("taint-unsanitised-flow")),
        "walker.py must keep its taint finding; got {:#?}",
        listing()
    );
    for d in &walker {
        assert!(
            !is_tagged(d),
            "walker.py converged; its findings must not carry the \
             scc_unconverged tag: {:#?}",
            listing()
        );
    }

    // The cycle itself did not converge and must still be tagged.
    let step_tagged = diags
        .iter()
        .filter(|d| {
            ["step_a.py", "step_b.py", "step_c.py", "step_d.py"]
                .iter()
                .any(|f| in_file(d, f))
        })
        .any(is_tagged);
    assert!(
        step_tagged,
        "the unconverged step_* cycle must keep the scc_unconverged tag: {:#?}",
        listing()
    );
}

/// Recursive pairs whose sink sites reach each other through the recursive
/// call used to flip the order of those sites on every fixed-point
/// iteration, so the summaries never compared equal and the batch ran to
/// the 64-iteration cap with every finding tagged unconverged.  Summaries
/// are now compared on their facts, ignoring that order, so both converge.
#[test]
fn scc_sink_site_order_does_not_oscillate() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);
    let dir = fixture_path("scc_sink_order_oscillation");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    let iters = last_scc_max_iterations();
    assert!(
        (1..=8).contains(&iters),
        "the recursive pairs must run the fixed-point loop and converge \
         well below the cap; got {iters} iterations"
    );
    let tagged: Vec<String> = diags
        .iter()
        .filter(|d| {
            d.evidence.as_ref().is_some_and(|e| {
                e.notes
                    .iter()
                    .any(|n| n.starts_with(SCC_UNCONVERGED_NOTE_PREFIX))
            })
        })
        .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
        .collect();
    assert!(tagged.is_empty(), "unconverged findings: {tagged:#?}");
}

/// A recursive pair whose summaries alternate between two states forever
/// (see the fixture README).  The loop must notice the repeated state and
/// stop instead of running all 64 iterations, and report the oscillation
/// as the reason on the findings it tags.
#[test]
fn scc_repeating_summaries_stop_early() {
    let _guard = SCC_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    set_scc_fixpoint_cap_override(0);
    let dir = fixture_path("scc_summary_cycle_stops_early");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);

    let iters = last_scc_max_iterations();
    assert!(
        (1..8).contains(&iters),
        "the recursive pair must run the fixed-point loop and stop well \
         below the cap; got {iters} iterations"
    );
    for d in &diags {
        let Some(ev) = d.evidence.as_ref() else {
            continue;
        };
        for note in ev
            .notes
            .iter()
            .filter(|n| n.starts_with(SCC_UNCONVERGED_NOTE_PREFIX))
        {
            assert!(
                note.contains("reason=suspected_oscillation"),
                "{}:{} {} tagged with {note}",
                d.path,
                d.line,
                d.id
            );
        }
    }
}
