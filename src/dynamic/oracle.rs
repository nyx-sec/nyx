//! Verdict oracle — how a sandbox run becomes Confirmed / NotConfirmed.
//!
//! Phase 06 (Track C.1) introduces the structured [`Oracle::SinkProbe`]
//! path: each curated payload supplies a small set of
//! [`ProbePredicate`]s; the runner drains the
//! [`crate::dynamic::probe::ProbeChannel`] after every payload run and
//! evaluates the predicates against the captured arguments.  A run is
//! Confirmed iff at least one drained record satisfies *every* predicate.
//!
//! The legacy [`Oracle::OutputContains`] path is retained for fixtures that
//! pre-date Phase 06 and migrated downstream; it is marked
//! `#[deprecated]` so the compiler nags every new use-site.

use crate::dynamic::probe::SinkProbe;
use crate::dynamic::sandbox::SandboxOutcome;

/// Predicate evaluated against a single [`SinkProbe`] when the oracle is
/// [`Oracle::SinkProbe`].
///
/// Fields use `&'static str` so the corpus can declare predicate slices
/// in `const` context — there is no allocation cost at scan time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePredicate {
    /// Captured arg at `index` contains `needle` as a substring.  String
    /// view of the arg is taken via [`super::probe::ProbeArg::as_str`].
    ArgContains { index: usize, needle: &'static str },
    /// Captured arg at `index` is byte-for-byte equal to `value`.
    ArgEquals { index: usize, value: &'static str },
    /// At least one captured arg contains `needle`.  Useful when the sink
    /// signature varies (e.g. variadic `printf`).
    AnyArgContains(&'static str),
    /// The probe's `sink_callee` field is byte-for-byte equal to `value`.
    CalleeEquals(&'static str),
    /// The probe records at least `min_args` arguments.  Lets a payload
    /// pin the sink's arity without locking exact values.
    MinArgs(usize),
}

/// How we decide a sandbox run confirmed the sink fired.
#[derive(Debug, Clone)]
pub enum Oracle {
    /// Structured: drain the probe channel and apply `predicates`.
    /// `predicates: &'static [ProbePredicate]` keeps the corpus
    /// declaration `const`-friendly (Phase 06 deferred the
    /// `Vec<ProbePredicate>` shape the plan listed because the corpus is
    /// declared in static memory; a `Vec` would require runtime init).
    SinkProbe { predicates: &'static [ProbePredicate] },
    /// Legacy stdout/stderr substring oracle.  Kept for fixtures that
    /// pre-date Phase 06; new payloads should prefer
    /// [`Oracle::SinkProbe`] which is robust to oracle collisions.
    #[deprecated(
        note = "use Oracle::SinkProbe with ProbePredicate args; OutputContains is brittle to oracle collisions (§16.3)"
    )]
    OutputContains(&'static str),
    /// Process exited with a crash signal (SIGSEGV, SIGABRT).
    Crash,
    /// Outbound network connection observed at the controlled sink host.
    OobCallback { host: &'static str },
    /// File written outside the sandbox root.
    FileEscape,
    /// Non-zero exit with specific status.
    ExitStatus(i32),
}

/// Evaluate an oracle against a single sandbox outcome plus the records
/// drained from the run's probe channel.  Returns `true` iff the run is
/// considered to have fired the sink.
#[allow(deprecated)]
pub fn oracle_fired(oracle: &Oracle, outcome: &SandboxOutcome, probes: &[SinkProbe]) -> bool {
    match oracle {
        Oracle::SinkProbe { predicates } => probes
            .iter()
            .any(|p| probe_satisfies_all(p, predicates)),
        Oracle::OutputContains(needle) => {
            let nb = needle.as_bytes();
            contains_subslice(&outcome.stdout, nb) || contains_subslice(&outcome.stderr, nb)
        }
        Oracle::Crash => outcome.exit_code.is_none() && !outcome.timed_out,
        Oracle::OobCallback { .. } => outcome.oob_callback_seen,
        Oracle::FileEscape => false,
        Oracle::ExitStatus(code) => outcome.exit_code == Some(*code),
    }
}

/// Returns true when `probe` satisfies *every* predicate in `preds`.
/// An empty predicate slice satisfies vacuously — a payload that wants
/// "any probe at all" can ship an empty predicate set.
pub fn probe_satisfies_all(probe: &SinkProbe, preds: &[ProbePredicate]) -> bool {
    preds.iter().all(|p| probe_satisfies_one(probe, p))
}

fn probe_satisfies_one(probe: &SinkProbe, pred: &ProbePredicate) -> bool {
    match pred {
        ProbePredicate::ArgContains { index, needle } => probe
            .args
            .get(*index)
            .and_then(|a| a.as_str())
            .map(|s| s.contains(*needle))
            .unwrap_or(false),
        ProbePredicate::ArgEquals { index, value } => probe
            .args
            .get(*index)
            .and_then(|a| a.as_str())
            .map(|s| s == *value)
            .unwrap_or(false),
        ProbePredicate::AnyArgContains(needle) => probe
            .args
            .iter()
            .any(|a| a.as_str().map(|s| s.contains(*needle)).unwrap_or(false)),
        ProbePredicate::CalleeEquals(value) => probe.sink_callee == *value,
        ProbePredicate::MinArgs(n) => probe.args.len() >= *n,
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::probe::{ProbeArg, SinkProbe};
    use std::time::Duration;

    fn outcome() -> SandboxOutcome {
        SandboxOutcome {
            exit_code: Some(0),
            stdout: vec![],
            stderr: vec![],
            timed_out: false,
            oob_callback_seen: false,
            sink_hit: false,
            duration: Duration::from_millis(1),
        }
    }

    fn probe(callee: &str, args: Vec<ProbeArg>) -> SinkProbe {
        SinkProbe {
            sink_callee: callee.into(),
            args,
            captured_at_ns: 1,
            payload_id: "test".into(),
        }
    }

    #[test]
    fn sink_probe_fires_when_predicates_match() {
        let oracle = Oracle::SinkProbe {
            predicates: &[
                ProbePredicate::CalleeEquals("os.system"),
                ProbePredicate::ArgContains { index: 0, needle: "; echo" },
            ],
        };
        let probes = vec![probe(
            "os.system",
            vec![ProbeArg::String("; echo NYX_PWN".into())],
        )];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn sink_probe_not_fired_with_no_probes() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::CalleeEquals("os.system")],
        };
        assert!(!oracle_fired(&oracle, &outcome(), &[]));
    }

    #[test]
    fn sink_probe_requires_all_predicates() {
        let oracle = Oracle::SinkProbe {
            predicates: &[
                ProbePredicate::CalleeEquals("os.system"),
                ProbePredicate::ArgContains { index: 0, needle: "NEVER_PRESENT" },
            ],
        };
        let probes = vec![probe(
            "os.system",
            vec![ProbeArg::String("hello".into())],
        )];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn any_arg_contains_matches_second_arg() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::AnyArgContains("password")],
        };
        let probes = vec![probe(
            "exec",
            vec![
                ProbeArg::String("benign".into()),
                ProbeArg::String("leaked password".into()),
            ],
        )];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn min_args_predicate() {
        let probes_two = vec![probe(
            "exec",
            vec![ProbeArg::String("a".into()), ProbeArg::String("b".into())],
        )];
        let probes_one = vec![probe("exec", vec![ProbeArg::String("a".into())])];
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::MinArgs(2)],
        };
        assert!(oracle_fired(&oracle, &outcome(), &probes_two));
        assert!(!oracle_fired(&oracle, &outcome(), &probes_one));
    }

    #[test]
    fn empty_predicate_set_matches_any_probe() {
        let oracle = Oracle::SinkProbe { predicates: &[] };
        let probes = vec![probe("anything", vec![])];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    #[allow(deprecated)]
    fn output_contains_legacy_still_works() {
        let mut o = outcome();
        o.stdout = b"NYX_OK".to_vec();
        let oracle = Oracle::OutputContains("NYX_OK");
        assert!(oracle_fired(&oracle, &o, &[]));
    }

    #[test]
    fn arg_equals_predicate() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::ArgEquals { index: 0, value: "exact" }],
        };
        let hit = vec![probe("f", vec![ProbeArg::String("exact".into())])];
        let miss = vec![probe("f", vec![ProbeArg::String("inexact".into())])];
        assert!(oracle_fired(&oracle, &outcome(), &hit));
        assert!(!oracle_fired(&oracle, &outcome(), &miss));
    }
}
