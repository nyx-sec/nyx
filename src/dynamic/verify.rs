//! Top-level entry point for the dynamic layer.
//!
//! The CLI subcommand and any library consumer call [`verify_finding`].
//! It is the only function the rest of the crate needs to know about.

use crate::commands::scan::Diag;
use crate::dynamic::report::{AttemptSummary, VerifyResult, VerifyStatus};
use crate::dynamic::runner::{run_spec, RunError};
use crate::dynamic::sandbox::SandboxOptions;
use crate::dynamic::spec::HarnessSpec;
use crate::evidence::UnsupportedReason;
use crate::utils::config::Config;

#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub sandbox: SandboxOptions,
}

impl VerifyOptions {
    /// Build `VerifyOptions` from scanner config.
    ///
    /// Currently forwards sandbox timeout from `config.scanner`; future
    /// milestones will add image/resource limits here.
    pub fn from_config(_config: &Config) -> Self {
        Self {
            sandbox: SandboxOptions::default(),
        }
    }
}

/// Try to dynamically confirm a static finding.
///
/// Never fails: every error path collapses into a [`VerifyStatus`] so the
/// caller can treat dynamic verification as best-effort enrichment.
pub fn verify_finding(diag: &Diag, opts: &VerifyOptions) -> VerifyResult {
    // Use the stable hash to identify the finding so the VerifyResult's
    // finding_id matches HarnessSpec::finding_id (both use the same hex form).
    let finding_id = format!("{:016x}", diag.stable_hash);

    let spec = match HarnessSpec::from_finding(diag) {
        Ok(s) => s,
        Err(reason) => {
            return VerifyResult {
                finding_id,
                status: VerifyStatus::Unsupported,
                triggered_payload: None,
                reason: Some(reason),
                detail: None,
                attempts: vec![],
            };
        }
    };

    // Spec derivable, but no backend implementation exists yet.
    // Phase M1 always lands here; real execution starts in Phase M2.
    let _ = &opts.sandbox;
    match run_spec(&spec, &opts.sandbox) {
        Ok(run) => {
            let attempts = run
                .attempts
                .iter()
                .map(|a| AttemptSummary {
                    payload_label: a.payload_label.to_string(),
                    exit_code: a.outcome.exit_code,
                    timed_out: a.outcome.timed_out,
                    triggered: a.triggered,
                })
                .collect();

            match run.triggered_by {
                Some(i) => VerifyResult {
                    finding_id,
                    status: VerifyStatus::Confirmed,
                    triggered_payload: Some(run.attempts[i].payload_label.to_string()),
                    reason: None,
                    detail: None,
                    attempts,
                },
                None => VerifyResult {
                    finding_id,
                    status: VerifyStatus::NotConfirmed,
                    triggered_payload: None,
                    reason: None,
                    detail: None,
                    attempts,
                },
            }
        }
        Err(RunError::NoPayloadsForCap) => VerifyResult {
            finding_id,
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some(UnsupportedReason::NoPayloadsForCap),
            detail: None,
            attempts: vec![],
        },
        Err(RunError::Harness(_)) => VerifyResult {
            finding_id,
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some(UnsupportedReason::BackendUnavailable),
            detail: None,
            attempts: vec![],
        },
        Err(RunError::Sandbox(e)) => VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            detail: Some(format!("sandbox failed: {e:?}")),
            attempts: vec![],
        },
    }
}
