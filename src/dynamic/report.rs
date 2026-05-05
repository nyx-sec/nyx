//! Verdict types returned by the dynamic layer.
//!
//! Kept separate from the run pipeline so the CLI / JSON output side can
//! depend on this without pulling in sandbox or harness deps.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyStatus {
    /// Sink fired with at least one payload. Static finding is exploitable
    /// against the live target.
    Confirmed,
    /// All payloads ran cleanly. Either the path is infeasible at runtime
    /// or the corpus is too narrow. Treat as "static-only" not "false".
    NotConfirmed,
    /// Could not build, run, or observe (toolchain missing, sandbox refused,
    /// timeout on every attempt, etc.).
    Inconclusive,
    /// We do not yet know how to drive this finding (missing language
    /// support, unsupported entry kind, no payloads for cap).
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub finding_id: String,
    pub status: VerifyStatus,
    /// Label of the payload that triggered, when [`VerifyStatus::Confirmed`].
    pub triggered_payload: Option<String>,
    /// Free-form note for inconclusive/unsupported cases.
    pub reason: Option<String>,
    /// Per-attempt log (payload label, exit code, timed_out flag).
    pub attempts: Vec<AttemptSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptSummary {
    pub payload_label: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub triggered: bool,
}
