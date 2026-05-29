//! Phase 24 / Track P.0 acceptance tests for cap-routed concurrency lanes.
//!
//! The headline gate: a 64-finding mixed-cap batch run through
//! [`WorkerPool::run_in_lanes`] beats a single-lane (one-queue) baseline by
//! ≥ 3×, because a slow `DESERIALIZE` harness can no longer head-of-line
//! block the fast `SSRF` ones — every cap drains its own lanes concurrently.
//!
//! The perf assertion is `#[ignore]` so the default suite stays hermetic and
//! fast; the ordering/correctness check runs by default.

#![cfg(feature = "dynamic")]

use std::time::{Duration, Instant};

use nyx_scanner::dynamic::runner::WorkerPool;
use nyx_scanner::labels::Cap;

/// Realistic OWASP-scale mix: mostly parallelisable `SSRF`, a minority of slow
/// `DESERIALIZE`, and a few single-lane `CRYPTO`.
fn mixed_batch() -> Vec<Cap> {
    (0..64)
        .map(|i| match i % 8 {
            0 => Cap::DESERIALIZE,
            1 => Cap::CRYPTO,
            _ => Cap::SSRF,
        })
        .collect()
}

/// Simulated per-finding verify cost: `DESERIALIZE` is the slow JVM/gadget
/// harness; everything else is cheap.
fn simulated_cost(cap: Cap) -> Duration {
    if cap.contains(Cap::DESERIALIZE) {
        Duration::from_millis(24)
    } else {
        Duration::from_millis(4)
    }
}

#[test]
fn run_in_lanes_preserves_order_and_runs_all() {
    let batch = mixed_batch();
    let out = WorkerPool::run_in_lanes(&batch, None, |c| *c, |i, _| i * 2);
    assert_eq!(out.len(), batch.len());
    // Output indexed by input position regardless of lane scheduling.
    assert_eq!(out, (0..batch.len()).map(|i| i * 2).collect::<Vec<_>>());
}

#[test]
#[ignore = "Phase 24 perf bench: 64-finding mixed-cap batch ≥ 3× vs single-lane. Opt-in so the default suite stays hermetic + fast. Run: cargo nextest run --features dynamic --run-ignored ignored-only -E 'binary(~workdir_clone)'"]
fn cap_lanes_beat_single_lane_by_3x() {
    let batch = mixed_batch();

    // Single-lane baseline: one queue, strictly sequential — the pre-P.0
    // behaviour where a slow cap blocks the whole batch.
    let t0 = Instant::now();
    let mut baseline_out = Vec::with_capacity(batch.len());
    for (i, c) in batch.iter().enumerate() {
        std::thread::sleep(simulated_cost(*c));
        baseline_out.push(i);
    }
    let single_lane = t0.elapsed();

    // Cap-routed lanes: every cap runs concurrently with its own worker budget.
    let t1 = Instant::now();
    let lane_out = WorkerPool::run_in_lanes(
        &batch,
        None,
        |c| *c,
        |i, c| {
            std::thread::sleep(simulated_cost(*c));
            i
        },
    );
    let lanes = t1.elapsed();

    assert_eq!(
        lane_out, baseline_out,
        "lanes must produce identical ordered results"
    );

    let speedup = single_lane.as_secs_f64() / lanes.as_secs_f64();
    eprintln!(
        "phase24 cap-lanes: single-lane {single_lane:.2?}, cap-lanes {lanes:.2?}, speedup {speedup:.2}×"
    );
    assert!(
        lanes.as_secs_f64() * 3.0 <= single_lane.as_secs_f64(),
        "phase24 acceptance gate: expected ≥ 3× speedup, got {speedup:.2}× (single={single_lane:?}, lanes={lanes:?})",
    );
}
