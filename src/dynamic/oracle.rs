//! Verdict oracle — how a sandbox run becomes Confirmed / NotConfirmed.
//!
//! Phase 06 (Track C.1) introduces the structured [`Oracle::SinkProbe`]
//! path: each curated payload supplies a small set of
//! [`ProbePredicate`]s; the runner drains the
//! [`crate::dynamic::probe::ProbeChannel`] after every payload run and
//! evaluates the predicates against the captured arguments.  A run is
//! Confirmed iff at least one drained record satisfies *every* predicate.
//!
//! Phase 08 (Track C.4) replaces the coarse [`Oracle::Crash`] with
//! [`Oracle::SinkCrash`].  The new variant only confirms when a probe
//! observation in the channel carries
//! [`crate::dynamic::probe::ProbeKind::Crash { signal }`] *and* the captured
//! signal is present in the payload's [`SignalSet`] — i.e. the SIGSEGV /
//! SIGABRT / etc. must have been caught by a sink-site signal handler, not
//! by random crashing setup code.  A process-level abort that escapes the
//! sink handler leaves no Crash probe, the oracle does not fire, and the
//! runner downgrades the verdict to
//! [`crate::evidence::InconclusiveReason::UnrelatedCrash`] instead of
//! stamping `Confirmed`.
//!
//! The legacy [`Oracle::OutputContains`] and [`Oracle::Crash`] paths are
//! retained for fixtures that pre-date Phase 06 / Phase 08 and migrated
//! downstream; both are marked `#[deprecated]` so the compiler nags every
//! new use-site.

use crate::dynamic::probe::{ProbeKind, SinkProbe};
use crate::dynamic::sandbox::SandboxOutcome;
use crate::dynamic::stubs::{StubEvent, StubKind};
use serde::{Deserialize, Serialize};

/// POSIX-style signal name carried inside [`ProbeKind::Crash`] and the
/// [`Oracle::SinkCrash`] match set.
///
/// Restricted to the signals a sink-site handler can plausibly catch and
/// route back through the probe channel.  Anything outside this enum (e.g.
/// `SIGKILL`, `SIGSTOP`) cannot be caught by a userspace handler and is
/// therefore not modellable as a confirmable crash signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signal {
    /// Segmentation fault.
    #[serde(rename = "SIGSEGV", alias = "Sigsegv", alias = "SEGV")]
    Sigsegv,
    /// Abort (typically from `abort(3)` or `assert(3)`).
    #[serde(rename = "SIGABRT", alias = "Sigabrt", alias = "ABRT")]
    Sigabrt,
    /// Bus error (misaligned access, mmap fault).
    #[serde(rename = "SIGBUS", alias = "Sigbus", alias = "BUS")]
    Sigbus,
    /// Floating-point exception (incl. integer divide-by-zero on x86).
    #[serde(rename = "SIGFPE", alias = "Sigfpe", alias = "FPE")]
    Sigfpe,
    /// Illegal instruction.
    #[serde(rename = "SIGILL", alias = "Sigill", alias = "ILL")]
    Sigill,
}

impl Signal {
    /// Bit position of `self` inside a [`SignalSet`].  Stable across builds
    /// so the wire format of a serialised [`SignalSet`] stays compatible.
    pub const fn bit(self) -> u8 {
        match self {
            Signal::Sigsegv => 0,
            Signal::Sigabrt => 1,
            Signal::Sigbus => 2,
            Signal::Sigfpe => 3,
            Signal::Sigill => 4,
        }
    }

    /// Render a [`Signal`] as the conventional uppercase POSIX name (e.g.
    /// `"SIGSEGV"`).  Used by the per-language probe shims so their
    /// captured `signal` strings are identical to what the host-side
    /// [`Signal::from_name`] decoder expects.
    pub const fn as_name(self) -> &'static str {
        match self {
            Signal::Sigsegv => "SIGSEGV",
            Signal::Sigabrt => "SIGABRT",
            Signal::Sigbus => "SIGBUS",
            Signal::Sigfpe => "SIGFPE",
            Signal::Sigill => "SIGILL",
        }
    }

    /// Inverse of [`as_name`](Signal::as_name).  Matches both the canonical
    /// uppercase form and a couple of common variants emitted by language
    /// runtimes (`"sigsegv"`, `"Segmentation fault"`).  Returns `None` for
    /// signals the oracle does not model.
    pub fn from_name(s: &str) -> Option<Signal> {
        let upper = s.trim().to_ascii_uppercase();
        match upper.as_str() {
            "SIGSEGV" | "SEGV" | "SEGMENTATION FAULT" => Some(Signal::Sigsegv),
            "SIGABRT" | "ABRT" | "ABORTED" => Some(Signal::Sigabrt),
            "SIGBUS" | "BUS" | "BUS ERROR" => Some(Signal::Sigbus),
            "SIGFPE" | "FPE" | "FLOATING POINT EXCEPTION" => Some(Signal::Sigfpe),
            "SIGILL" | "ILL" | "ILLEGAL INSTRUCTION" => Some(Signal::Sigill),
            _ => None,
        }
    }
}

/// Bitset of [`Signal`]s the [`Oracle::SinkCrash`] variant treats as
/// confirmable.  Stored as a `u8` so a `const`-declared corpus entry can
/// build the set without runtime allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalSet(u8);

impl SignalSet {
    /// Empty set — no signal is confirmable.  Mostly useful in tests as a
    /// "this oracle should never fire" baseline.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Set built from a slice of [`Signal`]s, callable from `const`
    /// context.  Order-independent; duplicates are collapsed.
    pub const fn from_slice(sigs: &[Signal]) -> Self {
        let mut bits = 0u8;
        let mut i = 0;
        while i < sigs.len() {
            bits |= 1 << sigs[i].bit();
            i += 1;
        }
        Self(bits)
    }

    /// `SignalSet` containing every modelled signal.  Default for payloads
    /// whose crash-on-arbitrary-input is the actual vulnerability (e.g. C
    /// memory corruption fuzzed via libFuzzer).
    pub const fn all() -> Self {
        Self::from_slice(&[
            Signal::Sigsegv,
            Signal::Sigabrt,
            Signal::Sigbus,
            Signal::Sigfpe,
            Signal::Sigill,
        ])
    }

    /// True iff `sig` is in the set.
    pub const fn contains(self, sig: Signal) -> bool {
        (self.0 & (1 << sig.bit())) != 0
    }

    /// True iff the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

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
    /// Phase 10 (Track D.3): predicate that fires when at least one
    /// [`StubEvent`] of kind `kind` carries a summary containing
    /// `needle`.  Lets a payload assert that a boundary stub (SQL, HTTP,
    /// Redis, filesystem) actually observed the sink's effect — e.g.
    /// `StubEventMatches { kind: StubKind::Sql, needle: "SELECT" }`.
    ///
    /// Evaluation is *cross-cutting*: predicates that target stub events
    /// satisfy vacuously when no stub events were drained (they cannot
    /// fail against a single probe).  Callers wanting per-probe pinning
    /// pair this with another predicate that does anchor to the probe.
    StubEventMatches {
        /// Which stub kind to look at.
        kind: StubKind,
        /// Substring to find in `StubEvent::summary`.
        needle: &'static str,
    },
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
    /// Phase 08 sink-site crash oracle.  Fires iff at least one drained
    /// probe has [`ProbeKind::Crash { signal }`] with `signal ∈ signals`.
    /// A process-level abort that did not reach the sink handler leaves no
    /// matching probe and the run does *not* confirm — the runner maps
    /// that case to [`crate::evidence::InconclusiveReason::UnrelatedCrash`].
    SinkCrash { signals: SignalSet },
    /// Legacy stdout/stderr substring oracle.  Kept for fixtures that
    /// pre-date Phase 06; new payloads should prefer
    /// [`Oracle::SinkProbe`] which is robust to oracle collisions.
    #[deprecated(
        note = "use Oracle::SinkProbe with ProbePredicate args; OutputContains is brittle to oracle collisions (§16.3)"
    )]
    OutputContains(&'static str),
    /// Process exited with any crash signal (SIGSEGV, SIGABRT).
    ///
    /// Coarse: fires on *any* uncaught crash, including ones unrelated to
    /// the sink (e.g. `abort()` in setup code).  Phase 08 introduces
    /// [`Oracle::SinkCrash`] which scopes the signal to the sink handler;
    /// new payloads should migrate.
    #[deprecated(
        note = "use Oracle::SinkCrash with a SignalSet; Crash confirms on any process abort, including setup-code failures (Phase 08 §C.4)"
    )]
    Crash,
    /// Outbound network connection observed at the controlled sink host.
    OobCallback { host: &'static str },
    /// File written outside the sandbox root.
    FileEscape,
    /// Non-zero exit with specific status.
    ExitStatus(i32),
    /// Phase 10 (Track D.3): boundary-stub-driven oracle.  Fires when the
    /// per-kind [`StubEvent`] log drained from
    /// [`crate::dynamic::stubs::StubHarness`] contains an event of
    /// `kind` whose summary contains `needle`.
    ///
    /// Distinct from the [`ProbePredicate::StubEventMatches`] *inside*
    /// `SinkProbe` evaluation: this variant lets a payload skip probe
    /// instrumentation entirely and confirm purely on the stub's
    /// observed effect, which is the only signal available for sinks
    /// the harness cannot wrap (e.g. opaque ORM calls).
    StubEvent {
        /// Which stub kind to look at.
        kind: StubKind,
        /// Substring to find in `StubEvent::summary`.
        needle: &'static str,
    },
}

/// Evaluate an oracle against a single sandbox outcome plus the records
/// drained from the run's probe channel.  Returns `true` iff the run is
/// considered to have fired the sink.
///
/// Backwards-compatible entry point — preserved verbatim for the
/// runner's vuln + benign-control loops that pre-date Phase 10's stub
/// layer.  When the active oracle inspects stub events (i.e.
/// [`Oracle::StubEvent`]) callers should use
/// [`oracle_fired_with_stubs`] which threads in a `&[StubEvent]`
/// slice; this function treats the stub-event log as empty so the
/// `Oracle::StubEvent` branch never fires under the legacy entry.
#[allow(deprecated)]
pub fn oracle_fired(oracle: &Oracle, outcome: &SandboxOutcome, probes: &[SinkProbe]) -> bool {
    oracle_fired_with_stubs(oracle, outcome, probes, &[])
}

/// Phase 10: evaluate an oracle with the boundary-stub event log in
/// scope.  See [`Oracle::StubEvent`] for the semantics of the new
/// branch and [`ProbePredicate::StubEventMatches`] for the new
/// `Oracle::SinkProbe` cross-cutting predicate.
#[allow(deprecated)]
pub fn oracle_fired_with_stubs(
    oracle: &Oracle,
    outcome: &SandboxOutcome,
    probes: &[SinkProbe],
    stub_events: &[StubEvent],
) -> bool {
    match oracle {
        Oracle::SinkProbe { predicates } => {
            // Predicate set split: per-probe vs cross-cutting (stub
            // events).  A predicate that targets stub events cannot be
            // evaluated against a single probe — it satisfies once
            // globally when the stub log contains a matching event.
            // Per-probe predicates must still hold for at least one
            // captured probe.
            let (cross, per_probe): (Vec<_>, Vec<_>) =
                predicates.iter().partition(|p| is_cross_cutting(p));
            let cross_ok = cross
                .iter()
                .all(|p| cross_cutting_satisfied(p, stub_events));
            if !cross_ok {
                return false;
            }
            match (cross.is_empty(), per_probe.is_empty()) {
                // Empty predicate slice — legacy semantics: fire when
                // at least one probe exists.
                (true, true) => !probes.is_empty(),
                // Only cross-cutting predicates, all satisfied → fire.
                (false, true) => true,
                // Per-probe predicates present — at least one probe
                // must satisfy every per-probe predicate.
                (_, false) => probes
                    .iter()
                    .any(|p| per_probe.iter().all(|pred| probe_satisfies_one(p, pred))),
            }
        }
        Oracle::SinkCrash { signals } => probes.iter().any(|p| match p.kind {
            ProbeKind::Crash { signal } => signals.contains(signal),
            ProbeKind::Normal => false,
        }),
        Oracle::OutputContains(needle) => {
            let nb = needle.as_bytes();
            contains_subslice(&outcome.stdout, nb) || contains_subslice(&outcome.stderr, nb)
        }
        Oracle::Crash => outcome.exit_code.is_none() && !outcome.timed_out,
        Oracle::OobCallback { .. } => outcome.oob_callback_seen,
        Oracle::FileEscape => false,
        Oracle::ExitStatus(code) => outcome.exit_code == Some(*code),
        Oracle::StubEvent { kind, needle } => stub_events
            .iter()
            .any(|e| e.kind == *kind && e.summary.contains(*needle)),
    }
}

/// True when `pred` evaluates against the stub-event log rather than
/// any single [`SinkProbe`].  Used to partition predicate slices in
/// [`oracle_fired_with_stubs`].
fn is_cross_cutting(pred: &ProbePredicate) -> bool {
    matches!(pred, ProbePredicate::StubEventMatches { .. })
}

fn cross_cutting_satisfied(pred: &ProbePredicate, stub_events: &[StubEvent]) -> bool {
    match pred {
        ProbePredicate::StubEventMatches { kind, needle } => stub_events
            .iter()
            .any(|e| e.kind == *kind && e.summary.contains(*needle)),
        _ => true,
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
        // Cross-cutting predicate; not evaluable against a single probe.
        // [`oracle_fired_with_stubs`] handles it via the partition path.
        ProbePredicate::StubEventMatches { .. } => true,
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

/// Convenience: returns the [`Signal`] captured by a [`SinkProbe`] when
/// its kind is `Crash`, else `None`.  Used by the runner to distinguish
/// "process crashed but no matching sink-site probe" (→
/// `Inconclusive(UnrelatedCrash)`) from "process crashed and a sink-site
/// probe matched" (→ `Confirmed` via `Oracle::SinkCrash`).
pub fn probe_crash_signal(probe: &SinkProbe) -> Option<Signal> {
    match probe.kind {
        ProbeKind::Crash { signal } => Some(signal),
        ProbeKind::Normal => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::probe::{ProbeArg, ProbeKind, ProbeWitness, SinkProbe};
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
            kind: ProbeKind::Normal,
            witness: ProbeWitness::empty(),
        }
    }

    fn crash_probe(callee: &str, signal: Signal) -> SinkProbe {
        SinkProbe {
            sink_callee: callee.into(),
            args: vec![],
            captured_at_ns: 1,
            payload_id: "test".into(),
            kind: ProbeKind::Crash { signal },
            witness: ProbeWitness::empty(),
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

    #[test]
    fn signal_set_round_trips_via_const_slice() {
        const SIGS: SignalSet = SignalSet::from_slice(&[Signal::Sigsegv, Signal::Sigabrt]);
        assert!(SIGS.contains(Signal::Sigsegv));
        assert!(SIGS.contains(Signal::Sigabrt));
        assert!(!SIGS.contains(Signal::Sigfpe));
        assert!(!SIGS.is_empty());
        assert!(SignalSet::empty().is_empty());
    }

    #[test]
    fn signal_set_all_contains_every_modelled_signal() {
        let all = SignalSet::all();
        for s in [
            Signal::Sigsegv,
            Signal::Sigabrt,
            Signal::Sigbus,
            Signal::Sigfpe,
            Signal::Sigill,
        ] {
            assert!(all.contains(s), "SignalSet::all missing {s:?}");
        }
    }

    #[test]
    fn signal_from_name_matches_canonical_and_lowercase() {
        assert_eq!(Signal::from_name("SIGSEGV"), Some(Signal::Sigsegv));
        assert_eq!(Signal::from_name("  sigsegv  "), Some(Signal::Sigsegv));
        assert_eq!(Signal::from_name("Aborted"), Some(Signal::Sigabrt));
        assert_eq!(Signal::from_name("nope"), None);
    }

    #[test]
    fn sink_crash_confirms_only_on_matching_signal_probe() {
        let oracle = Oracle::SinkCrash {
            signals: SignalSet::from_slice(&[Signal::Sigsegv]),
        };
        let probes = vec![crash_probe("victim", Signal::Sigsegv)];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn sink_crash_ignores_normal_probes() {
        let oracle = Oracle::SinkCrash {
            signals: SignalSet::all(),
        };
        let probes = vec![probe("victim", vec![ProbeArg::String("x".into())])];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn sink_crash_ignores_unrelated_signal() {
        let oracle = Oracle::SinkCrash {
            signals: SignalSet::from_slice(&[Signal::Sigsegv]),
        };
        let probes = vec![crash_probe("victim", Signal::Sigabrt)];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn sink_crash_without_probes_does_not_fire_even_on_process_crash() {
        let mut o = outcome();
        o.exit_code = None;
        o.timed_out = false;
        let oracle = Oracle::SinkCrash {
            signals: SignalSet::all(),
        };
        assert!(!oracle_fired(&oracle, &o, &[]));
    }
}
