//! Orchestration: spec -> harness -> sandbox -> oracle -> verdict.
//!
//! The runner is the only place that knows about all four submodules at
//! once. Everything below it (corpus, harness, sandbox) is independent;
//! everything above it ([`crate::dynamic::verify`]) just calls
//! [`run_spec`] and turns the result into a [`crate::dynamic::report::VerifyResult`].

use crate::dynamic::corpus::{payloads_for, Oracle};
use crate::dynamic::harness::{self, BuiltHarness, HarnessError};
use crate::dynamic::sandbox::{self, SandboxError, SandboxOptions, SandboxOutcome};
use crate::dynamic::spec::HarnessSpec;

#[derive(Debug)]
pub struct RunOutcome {
    pub spec: HarnessSpec,
    pub attempts: Vec<Attempt>,
    /// First attempt that fired the sink, if any.
    pub triggered_by: Option<usize>,
}

#[derive(Debug)]
pub struct Attempt {
    pub payload_label: &'static str,
    pub outcome: SandboxOutcome,
    pub triggered: bool,
}

#[derive(Debug)]
pub enum RunError {
    NoPayloadsForCap,
    Harness(HarnessError),
    Sandbox(SandboxError),
}

impl From<HarnessError> for RunError {
    fn from(e: HarnessError) -> Self {
        RunError::Harness(e)
    }
}

impl From<SandboxError> for RunError {
    fn from(e: SandboxError) -> Self {
        RunError::Sandbox(e)
    }
}

/// Build harness once, run every payload from the cap-matched corpus,
/// stop at first trigger.
pub fn run_spec(spec: &HarnessSpec, opts: &SandboxOptions) -> Result<RunOutcome, RunError> {
    let payloads = payloads_for(spec.expected_cap);
    if payloads.is_empty() {
        return Err(RunError::NoPayloadsForCap);
    }

    let harness: BuiltHarness = harness::build(spec)?;

    let mut attempts = Vec::with_capacity(payloads.len());
    let mut triggered_by = None;

    for (i, payload) in payloads.iter().enumerate() {
        let outcome = sandbox::run(&harness, payload, opts)?;
        let triggered = oracle_fired(&payload.oracle, &outcome);
        attempts.push(Attempt {
            payload_label: payload.label,
            outcome,
            triggered,
        });
        if triggered {
            triggered_by = Some(i);
            break;
        }
    }

    Ok(RunOutcome {
        spec: spec.clone(),
        attempts,
        triggered_by,
    })
}

fn oracle_fired(oracle: &Oracle, outcome: &SandboxOutcome) -> bool {
    match oracle {
        Oracle::OutputContains(needle) => {
            let nb = needle.as_bytes();
            contains_subslice(&outcome.stdout, nb) || contains_subslice(&outcome.stderr, nb)
        }
        Oracle::Crash => matches!(outcome.exit_code, None) && !outcome.timed_out,
        Oracle::OobCallback { .. } => outcome.oob_callback_seen,
        Oracle::FileEscape => false, // TODO(dynamic): wire fs watcher in sandbox layer.
        Oracle::ExitStatus(code) => outcome.exit_code == Some(*code),
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return needle.is_empty();
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

