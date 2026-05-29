//! Verify-pipeline trace (Phase 30 — Track C observability).
//!
//! [`VerifyTrace`] is a structured, deterministic record of every stage
//! a single [`crate::dynamic::verify::verify_finding`] call walks
//! through.  Two uses:
//!
//! 1. **`--verbose` stderr stream** — when
//!    [`crate::dynamic::verify::VerifyOptions::trace_verbose`] is set the
//!    verifier prints each event to stderr as it fires.  Operators see
//!    where a run stalled or which payload triggered without re-running
//!    under a debugger.
//! 2. **Repro bundle serialisation** — the trace is emitted into the
//!    Phase 28 repro bundle as `expected/trace.jsonl` so a replay knows
//!    the canonical sequence its run is expected to mirror.  Together
//!    with the Phase 27 `events.jsonl` log this gives a forensic
//!    "what did the verifier do?" picture that does not require
//!    re-running the binary.
//!
//! # Determinism contract
//!
//! `TraceEvent` deliberately omits wall-clock timestamps and durations
//! so two runs of the same finding produce a byte-identical sequence.
//! The Phase 30 acceptance test (`tests/determinism_audit.rs`) runs the
//! verifier 10× on a fixed input and asserts every serialised trace is
//! identical.  Elapsed-time annotations are still useful for the
//! stderr printer; they are computed inline at print time from
//! `Instant::now()` and never persisted.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Distinct stages emitted by the verifier.  The names match the Phase
/// 30 spec literal so audit logs grep for `oracle_observed` /
/// `verdict` directly.
///
/// Serialised as snake_case strings so the on-disk trace reads cleanly
/// in `jq` without a string-versus-enum decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStage {
    SpecStarted,
    SpecDone,
    /// Track L.0 — a [`crate::dynamic::framework::FrameworkAdapter`]
    /// claimed the spec's entry function.  `detail` carries the
    /// adapter name verbatim (e.g. `"flask"`, `"spring-mvc"`).
    FrameworkAdapterDetected,
    /// Track L.0 — no registered adapter matched the spec's entry
    /// function.  Emitted alongside [`Self::SpecDone`] for every spec
    /// so a trace consumer can audit framework-detection coverage by
    /// counting `framework_adapter_*` events.
    FrameworkAdapterNone,
    BuildStarted,
    BuildDone,
    SandboxStarted,
    OracleWait,
    OracleObserved,
    Verdict,
    /// Track P.0 — the verifier assigned this finding to a cap-routed
    /// concurrency lane.  `detail` carries `cap=<name> lane=<n>` so a
    /// trace consumer can audit how a mixed-cap batch fanned out across
    /// lanes without head-of-line blocking.
    WorkerLaneAssigned,
    /// Track K.0 (Phase 25) — the multi-strategy spec-derivation scoring
    /// picked a winning candidate.  `detail` carries
    /// `winner=<strategy> runners_up=<strategy,…>` so a trace consumer can
    /// audit which strategies fired and which lost the score / tie-break,
    /// making engine derivation gaps visible without re-running.
    SpecScoringResult,
}

impl TraceStage {
    /// Stable label used by the stderr printer.  Lowercase, no
    /// punctuation, so a CI log scan can grep `^[T] oracle_observed`
    /// straightforwardly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SpecStarted => "spec_started",
            Self::SpecDone => "spec_done",
            Self::FrameworkAdapterDetected => "framework_adapter_detected",
            Self::FrameworkAdapterNone => "framework_adapter_none",
            Self::BuildStarted => "build_started",
            Self::BuildDone => "build_done",
            Self::SandboxStarted => "sandbox_started",
            Self::OracleWait => "oracle_wait",
            Self::OracleObserved => "oracle_observed",
            Self::Verdict => "verdict",
            Self::WorkerLaneAssigned => "worker_lane_assigned",
            Self::SpecScoringResult => "spec_scoring_result",
        }
    }
}

/// One row of a [`VerifyTrace`].
///
/// `sequence` is the per-trace ordinal — explicit rather than implicit
/// in `Vec` order because the JSON-lines format on disk lets each line
/// stand alone (operators may sort / filter externally).  `detail` is
/// a short, human-friendly free-form note (payload label, build attempt
/// counter, …); kept under 200 chars by callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub sequence: u32,
    pub stage: TraceStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Ordered record of every stage the verifier walks through.
///
/// Append via [`VerifyTrace::record`] (thread-safe; protected by an
/// internal `Mutex` so the sandbox/runner thread and the verifier can
/// share the same handle).  Read deterministically via
/// [`VerifyTrace::events`].
#[derive(Debug, Default)]
pub struct VerifyTrace {
    inner: Mutex<TraceInner>,
}

#[derive(Debug, Default)]
struct TraceInner {
    events: Vec<TraceEvent>,
    next_sequence: u32,
}

impl VerifyTrace {
    /// Fresh, empty trace.  Cheap — no allocation until the first event.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `stage` with optional `detail`.  Lock-poisoning is treated
    /// as a no-op so a panicking caller does not corrupt downstream
    /// traces; the trace is observability, not load-bearing state.
    pub fn record(&self, stage: TraceStage, detail: Option<String>) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let sequence = inner.next_sequence;
        inner.next_sequence = sequence.wrapping_add(1);
        inner.events.push(TraceEvent {
            sequence,
            stage,
            detail,
        });
    }

    /// Snapshot the recorded events in append order.  Clones the vec so
    /// the caller can serialise / drain without holding the lock; the
    /// allocation is negligible compared to the rest of a verifier run.
    pub fn events(&self) -> Vec<TraceEvent> {
        match self.inner.lock() {
            Ok(g) => g.events.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// Serialise the trace as a JSON-lines string.  Each line is a
    /// single [`TraceEvent`] so the file is greppable and tolerant of
    /// truncation (any prefix is still valid JSON-lines).
    pub fn to_jsonl(&self) -> String {
        let events = self.events();
        let mut out = String::with_capacity(events.len() * 80);
        for ev in &events {
            // `serde_json::to_string` cannot fail for the field types
            // here (`u32`, fixed enum, optional `String`).
            if let Ok(line) = serde_json::to_string(ev) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }

    /// Best-effort stderr print of every recorded event, prefixed with
    /// `[T]` so a tail of a verify log can find trace rows quickly.
    /// Called when [`crate::dynamic::verify::VerifyOptions::trace_verbose`]
    /// is set.  Print failures are silently ignored because trace
    /// output is observability, not a verdict input.
    pub fn print_to_stderr(&self) {
        use std::io::Write;
        let events = self.events();
        let mut err = std::io::stderr().lock();
        for ev in &events {
            let detail = ev.detail.as_deref().unwrap_or("");
            let _ = writeln!(err, "[T] {} {} {}", ev.sequence, ev.stage.as_str(), detail);
        }
        let _ = err.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_assigns_monotonic_sequences() {
        let t = VerifyTrace::new();
        t.record(TraceStage::SpecStarted, None);
        t.record(TraceStage::SpecDone, Some("py.cmdi.os_system".to_owned()));
        t.record(TraceStage::Verdict, Some("Confirmed".to_owned()));
        let events = t.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[1].sequence, 1);
        assert_eq!(events[2].sequence, 2);
        assert_eq!(events[0].stage, TraceStage::SpecStarted);
        assert_eq!(events[2].stage, TraceStage::Verdict);
    }

    #[test]
    fn jsonl_is_deterministic_for_same_sequence() {
        let a = VerifyTrace::new();
        a.record(TraceStage::SpecStarted, None);
        a.record(TraceStage::Verdict, Some("NotConfirmed".to_owned()));
        let b = VerifyTrace::new();
        b.record(TraceStage::SpecStarted, None);
        b.record(TraceStage::Verdict, Some("NotConfirmed".to_owned()));
        assert_eq!(a.to_jsonl(), b.to_jsonl());
    }

    #[test]
    fn jsonl_round_trips_through_serde() {
        let t = VerifyTrace::new();
        t.record(
            TraceStage::SandboxStarted,
            Some("payload=sqli-tautology".to_owned()),
        );
        t.record(TraceStage::OracleObserved, Some("fired=true".to_owned()));
        let jsonl = t.to_jsonl();
        let mut parsed = Vec::new();
        for line in jsonl.lines() {
            let ev: TraceEvent = serde_json::from_str(line).expect("trace line should parse");
            parsed.push(ev);
        }
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].stage, TraceStage::SandboxStarted);
        assert_eq!(parsed[1].stage, TraceStage::OracleObserved);
    }

    #[test]
    fn stage_as_str_matches_spec_names() {
        // Phase 30 spec literal: the verifier stage names must serialise
        // to these exact tokens so audit grep queries stay stable.
        assert_eq!(TraceStage::SpecStarted.as_str(), "spec_started");
        assert_eq!(TraceStage::SpecDone.as_str(), "spec_done");
        assert_eq!(TraceStage::BuildStarted.as_str(), "build_started");
        assert_eq!(TraceStage::BuildDone.as_str(), "build_done");
        assert_eq!(TraceStage::SandboxStarted.as_str(), "sandbox_started");
        assert_eq!(TraceStage::OracleWait.as_str(), "oracle_wait");
        assert_eq!(TraceStage::OracleObserved.as_str(), "oracle_observed");
        assert_eq!(TraceStage::Verdict.as_str(), "verdict");
        assert_eq!(
            TraceStage::WorkerLaneAssigned.as_str(),
            "worker_lane_assigned"
        );
        assert_eq!(
            TraceStage::SpecScoringResult.as_str(),
            "spec_scoring_result"
        );
    }
}
