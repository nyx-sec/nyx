//! Top-level entry point for the dynamic layer.
//!
//! The CLI subcommand and any library consumer call [`verify_finding`].
//! It is the only function the rest of the crate needs to know about.

use crate::commands::scan::Diag;
use crate::dynamic::report::{AttemptSummary, VerifyResult, VerifyStatus};
use crate::dynamic::runner::{run_spec, RunError};
use crate::dynamic::sandbox::SandboxOptions;
use crate::dynamic::spec::HarnessSpec;

#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub sandbox: SandboxOptions,
}

/// Try to dynamically confirm a static finding.
///
/// Never fails: every error path collapses into a [`VerifyStatus`] so the
/// caller can treat dynamic verification as best-effort enrichment.
pub fn verify_finding(diag: &Diag, opts: &VerifyOptions) -> VerifyResult {
    let finding_id = diag.id.clone();

    let Some(spec) = HarnessSpec::from_finding(diag) else {
        return VerifyResult {
            finding_id,
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some("no harness spec derivable from finding".into()),
            attempts: vec![],
        };
    };

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
                    attempts,
                },
                None => VerifyResult {
                    finding_id,
                    status: VerifyStatus::NotConfirmed,
                    triggered_payload: None,
                    reason: None,
                    attempts,
                },
            }
        }
        Err(RunError::NoPayloadsForCap) => VerifyResult {
            finding_id,
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some("no payload corpus for sink cap".into()),
            attempts: vec![],
        },
        Err(RunError::Harness(e)) => VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: Some(format!("harness build failed: {e:?}")),
            attempts: vec![],
        },
        Err(RunError::Sandbox(e)) => VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: Some(format!("sandbox failed: {e:?}")),
            attempts: vec![],
        },
    }
}
