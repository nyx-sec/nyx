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
    /// Phase 03 (Track J.1): predicate that fires when at least one
    /// drained probe carries [`ProbeKind::Deserialize`] with
    /// `gadget_chain_invoked` matching `require_invoked`.  Cross-cutting
    /// in the same sense as [`Self::StubEventMatches`] — evaluation
    /// looks across every drained probe rather than asserting against a
    /// single record.
    DeserializeGadgetInvoked {
        /// `true` requires at least one Deserialize probe with
        /// `gadget_chain_invoked == true` (a benign control passing
        /// well-formed serialized data should never satisfy this).
        /// `false` lets a payload that intentionally exercises the
        /// "caught at boundary" path still confirm.
        require_invoked: bool,
    },
    /// Phase 04 (Track J.2): SSTI render-equality predicate.
    ///
    /// Fires when the harness's captured stdout body parses as JSON
    /// `{"render": "<integer>"}` and the integer equals `expected`.  The
    /// payload sends a template expression that resolves to a fixed
    /// constant only when the engine actually evaluates it (e.g.
    /// `{{7*7}}` → `49`); a benign control sends literal text that the
    /// engine echoes, producing a non-matching render value.
    ///
    /// Cross-cutting: evaluated against [`SandboxOutcome::stdout`]
    /// rather than any single [`SinkProbe`], so the predicate satisfies
    /// globally once per run.
    TemplateEvalEqual {
        /// Integer the rendered template body must equal for the
        /// oracle to fire.  Stored as `u64` so the corpus can pin
        /// engine-portable constants ranging up to `2^64 − 1` without
        /// signed-overflow concerns.
        expected: u64,
    },
    /// Phase 05 (Track J.3): XXE entity-expansion predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::Xxe`] with `entity_expanded` matching
    /// `require_expanded`.  The vuln payload ships an XML document
    /// with a `<!ENTITY xxe SYSTEM "file:///…">` declaration; the
    /// per-language harness's instrumented parser writes
    /// `entity_expanded: true` once the entity body materialises
    /// inside the parsed tree.  The benign control disables
    /// doctype / external-entity resolution so the parser refuses the
    /// expansion and writes `entity_expanded: false`.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] — evaluated across every
    /// drained probe rather than against a single record.
    XxeEntityExpanded {
        /// `true` requires at least one [`ProbeKind::Xxe`] probe with
        /// `entity_expanded == true` (the differential confirmation
        /// path); `false` lets a payload that intentionally exercises
        /// the parser-refusal benign control still confirm.
        require_expanded: bool,
    },
    /// Phase 08 (Track J.6): HTTP response-header CRLF-injection
    /// predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::HeaderEmit`] whose `name` equals `header_name` (or
    /// `header_name` is the wildcard `"*"`) and whose `value` contains
    /// a literal `\r\n` byte pair.  The vuln payload splices `\r\n`
    /// followed by an injected header line into the response writer's
    /// value argument; the per-language harness's instrumented
    /// `setHeader` records the unmodified bytes the host process
    /// passed in.  The benign control passes the same logical value
    /// through `URLEncoder.encode` / `urllib.parse.quote`, so the
    /// captured value carries `%0d%0a` (not the raw bytes) and the
    /// predicate stays clear.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] /
    /// [`Self::QueryResultCountGreaterThan`] — evaluated across every
    /// drained probe rather than against a single record.
    HeaderInjected {
        /// Header name the malicious payload targets (e.g.
        /// `"Set-Cookie"`, `"Location"`).  Use `"*"` to satisfy on any
        /// captured header whose value contains the CRLF pair.
        header_name: &'static str,
    },
    /// Phase 09 (Track J.7): open-redirect predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::Redirect`] whose extracted `location` host falls
    /// outside `allowlist`.  Same-origin redirects (the `location`
    /// host equals `request_host`, or the location is a relative
    /// path) never fire — they cannot leave the application origin
    /// regardless of allowlist contents.  Hosts are compared
    /// case-insensitively against the allowlist entries; schemeless
    /// `//host/...` references are parsed as off-origin.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] /
    /// [`Self::HeaderInjected`] — evaluated across every drained
    /// probe rather than against a single record.
    RedirectHostNotIn {
        /// Allowlist of origin hosts the application is willing to
        /// redirect into (e.g. `&["example.com", "www.example.com"]`).
        /// `request_host` is implicitly allowed even when absent
        /// from this slice.
        allowlist: &'static [&'static str],
    },
    /// Phase 06 (Track J.4) / Phase 07 (Track J.5): result-count
    /// predicate shared by LDAP-filter and XPath-expression injection.
    ///
    /// Fires when at least one drained probe carries a count-bearing
    /// kind — [`ProbeKind::Ldap`] with `entries_returned > n` or
    /// [`ProbeKind::Xpath`] with `nodes_returned > n`.  The malicious
    /// payload inflates the host expression (`*)(uid=*` for LDAP, `'
    /// or '1'='1` for XPath) so the in-sandbox directory / staged XML
    /// document matches every provisioned record (> 1 entry / node).
    /// The benign control quotes the filter / expression so the sink
    /// returns exactly one record, leaving the predicate clear.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] — evaluated across every drained
    /// probe rather than against a single record.
    QueryResultCountGreaterThan {
        /// Threshold the captured `entries_returned` /
        /// `nodes_returned` count must exceed to fire the predicate.
        /// Typically `1`: the originally-intended record is one
        /// match, any additional matches prove the filter /
        /// expression expanded into an over-broad selector.
        n: u32,
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
            // events, deserialize gadget invocation).  Cross-cutting
            // predicates cannot be evaluated against a single probe —
            // they satisfy once globally when the matching log shape is
            // present.  Per-probe predicates must still hold for at
            // least one captured probe.
            let (cross, per_probe): (Vec<_>, Vec<_>) =
                predicates.iter().partition(|p| is_cross_cutting(p));
            // Stub-event cross-cutting predicates.
            let stub_cross_ok = cross
                .iter()
                .all(|p| cross_cutting_satisfied(p, stub_events));
            if !stub_cross_ok {
                return false;
            }
            // Deserialize cross-cutting predicates.
            let deserialize_cross_ok = cross.iter().all(|p| match p {
                ProbePredicate::DeserializeGadgetInvoked { require_invoked } => {
                    probes_satisfy_deserialize(probes, *require_invoked)
                }
                _ => true,
            });
            if !deserialize_cross_ok {
                return false;
            }
            // Phase 05 (Track J.3): XXE entity-expansion cross-cutting
            // predicates.  Each `XxeEntityExpanded { require_expanded }`
            // consults the captured probe channel for a
            // [`ProbeKind::Xxe`] record whose `entity_expanded` flag
            // matches.
            let xxe_cross_ok = cross.iter().all(|p| match p {
                ProbePredicate::XxeEntityExpanded { require_expanded } => {
                    probes_satisfy_xxe(probes, *require_expanded)
                }
                _ => true,
            });
            if !xxe_cross_ok {
                return false;
            }
            // Phase 06 (Track J.4) + Phase 07 (Track J.5): result-
            // count cross-cutting predicates.  Each
            // `QueryResultCountGreaterThan { n }` consults the captured
            // probe channel for a [`ProbeKind::Ldap`] record whose
            // `entries_returned` exceeds `n` *or* a [`ProbeKind::Xpath`]
            // record whose `nodes_returned` exceeds `n`.
            let query_count_cross_ok = cross.iter().all(|p| match p {
                ProbePredicate::QueryResultCountGreaterThan { n } => {
                    probes_satisfy_count_gt(probes, *n)
                }
                _ => true,
            });
            if !query_count_cross_ok {
                return false;
            }
            // Phase 08 (Track J.6): header-injection cross-cutting
            // predicates.  Each `HeaderInjected { header_name }`
            // consults the captured probe channel for a
            // [`ProbeKind::HeaderEmit`] record whose `name` matches
            // and whose `value` contains a literal CRLF byte pair.
            let header_injected_ok = cross.iter().all(|p| match p {
                ProbePredicate::HeaderInjected { header_name } => {
                    probes_satisfy_header_injected(probes, header_name)
                }
                _ => true,
            });
            if !header_injected_ok {
                return false;
            }
            // Phase 09 (Track J.7): open-redirect cross-cutting
            // predicates.  Each `RedirectHostNotIn { allowlist }`
            // consults the captured probe channel for a
            // [`ProbeKind::Redirect`] record whose `location` host
            // resolves off-origin relative to `allowlist ∪
            // {request_host}`.
            let redirect_ok = cross.iter().all(|p| match p {
                ProbePredicate::RedirectHostNotIn { allowlist } => {
                    probes_satisfy_redirect_off_origin(probes, allowlist)
                }
                _ => true,
            });
            if !redirect_ok {
                return false;
            }
            // Phase 04 (Track J.2): SSTI render-equality cross-cutting
            // predicates.  Each `TemplateEvalEqual { expected }` consults
            // the captured stdout body — see [`stdout_template_equals`].
            let template_eval_ok = cross.iter().all(|p| match p {
                ProbePredicate::TemplateEvalEqual { expected } => {
                    stdout_template_equals(&outcome.stdout, *expected)
                }
                _ => true,
            });
            if !template_eval_ok {
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
        Oracle::SinkCrash { signals } => probes.iter().any(|p| match &p.kind {
            ProbeKind::Crash { signal } => signals.contains(*signal),
            ProbeKind::Normal
            | ProbeKind::Deserialize { .. }
            | ProbeKind::Xxe { .. }
            | ProbeKind::Ldap { .. }
            | ProbeKind::Xpath { .. }
            | ProbeKind::HeaderEmit { .. }
            | ProbeKind::Redirect { .. } => false,
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
    matches!(
        pred,
        ProbePredicate::StubEventMatches { .. }
            | ProbePredicate::DeserializeGadgetInvoked { .. }
            | ProbePredicate::TemplateEvalEqual { .. }
            | ProbePredicate::XxeEntityExpanded { .. }
            | ProbePredicate::QueryResultCountGreaterThan { .. }
            | ProbePredicate::HeaderInjected { .. }
            | ProbePredicate::RedirectHostNotIn { .. }
    )
}

fn cross_cutting_satisfied(pred: &ProbePredicate, stub_events: &[StubEvent]) -> bool {
    match pred {
        ProbePredicate::StubEventMatches { kind, needle } => stub_events
            .iter()
            .any(|e| e.kind == *kind && e.summary.contains(*needle)),
        // DeserializeGadgetInvoked is cross-cutting against the *probe
        // log* rather than stub events; evaluated separately in
        // [`probes_satisfy_deserialize`] below.
        ProbePredicate::DeserializeGadgetInvoked { .. } => true,
        // TemplateEvalEqual is cross-cutting against the *sandbox
        // outcome stdout* rather than stub events; evaluated separately
        // via [`stdout_template_equals`] in [`oracle_fired_with_stubs`].
        ProbePredicate::TemplateEvalEqual { .. } => true,
        // XxeEntityExpanded is cross-cutting against the *probe log*
        // rather than stub events; evaluated separately in
        // [`probes_satisfy_xxe`] below.
        ProbePredicate::XxeEntityExpanded { .. } => true,
        // QueryResultCountGreaterThan is cross-cutting against the
        // *probe log* rather than stub events; evaluated separately
        // in [`probes_satisfy_count_gt`] below.
        ProbePredicate::QueryResultCountGreaterThan { .. } => true,
        // HeaderInjected is cross-cutting against the *probe log*
        // rather than stub events; evaluated separately in
        // [`probes_satisfy_header_injected`] below.
        ProbePredicate::HeaderInjected { .. } => true,
        // RedirectHostNotIn is cross-cutting against the *probe log*
        // rather than stub events; evaluated separately in
        // [`probes_satisfy_redirect_off_origin`] below.
        ProbePredicate::RedirectHostNotIn { .. } => true,
        _ => true,
    }
}

/// Phase 04 (Track J.2): extract the `render` field from a JSON body
/// printed on the harness's stdout and compare it against `expected`.
///
/// The harness writes one JSON object per run shaped like
/// `{"render": "<integer>"}`.  The integer is encoded as a string so
/// engines that render integers as `"49"` (every supported engine does)
/// match the same wire format.  A run satisfies the predicate when:
///
/// 1. `stdout` contains at least one JSON object whose top-level
///    `render` field is a string, AND
/// 2. that string parses to a `u64` byte-for-byte equal to `expected`.
///
/// Stdout may contain other lines (warnings, debug prints) — the
/// matcher scans line-by-line and accepts the first parseable record.
/// A malformed body or missing field returns `false` rather than
/// surfacing an error so a benign control that never emitted any JSON
/// at all (the engine echoed plain text) does not accidentally fire.
fn stdout_template_equals(stdout: &[u8], expected: u64) -> bool {
    let text = match std::str::from_utf8(stdout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(trimmed);
        let Ok(v) = parsed else { continue };
        let Some(render) = v.get("render") else { continue };
        let Some(s) = render.as_str() else { continue };
        if let Ok(n) = s.trim().parse::<u64>() {
            if n == expected {
                return true;
            }
        }
    }
    false
}

/// True when at least one drained probe is a
/// [`ProbeKind::Deserialize`] record matching `require_invoked`.
fn probes_satisfy_deserialize(probes: &[SinkProbe], require_invoked: bool) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::Deserialize { gadget_chain_invoked } => {
            *gadget_chain_invoked == require_invoked
        }
        _ => false,
    })
}

/// True when at least one drained probe is a [`ProbeKind::Xxe`]
/// record matching `require_expanded`.
fn probes_satisfy_xxe(probes: &[SinkProbe], require_expanded: bool) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::Xxe { entity_expanded } => *entity_expanded == require_expanded,
        _ => false,
    })
}

/// True when at least one drained probe carries a query-count kind
/// whose count exceeds `n`.  Matches both [`ProbeKind::Ldap`]
/// (`entries_returned > n`) and [`ProbeKind::Xpath`]
/// (`nodes_returned > n`).
fn probes_satisfy_count_gt(probes: &[SinkProbe], n: u32) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::Ldap { entries_returned } => *entries_returned > n,
        ProbeKind::Xpath { nodes_returned } => *nodes_returned > n,
        _ => false,
    })
}

/// True when at least one drained probe is a
/// [`ProbeKind::HeaderEmit`] record whose `name` matches `header_name`
/// (or `header_name == "*"`) and whose `value` contains a literal
/// `\r\n` byte pair.  Powers
/// [`ProbePredicate::HeaderInjected`] (Phase 08 — Track J.6).
fn probes_satisfy_header_injected(probes: &[SinkProbe], header_name: &str) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::HeaderEmit { name, value } => {
            (header_name == "*" || name.eq_ignore_ascii_case(header_name))
                && value.contains("\r\n")
        }
        _ => false,
    })
}

/// True when at least one drained probe is a [`ProbeKind::Redirect`]
/// record whose extracted `location` host falls outside the
/// `allowlist ∪ {request_host}` set.  Powers
/// [`ProbePredicate::RedirectHostNotIn`] (Phase 09 — Track J.7).
///
/// Same-origin redirects (relative path, or absolute URL whose host
/// equals `request_host`) never fire — they cannot leave the
/// application origin regardless of allowlist contents.  Schemeless
/// `//host/...` references are parsed as off-origin.
fn probes_satisfy_redirect_off_origin(probes: &[SinkProbe], allowlist: &[&str]) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::Redirect { location, request_host } => {
            redirect_is_off_origin(location, request_host, allowlist)
        }
        _ => false,
    })
}

/// Returns `true` when `location` redirects to a host that is neither
/// `request_host` nor any entry of `allowlist`.  Crate-visible so the
/// in-crate predicate above and the colocated tests can share one
/// canonical off-origin check.
pub(crate) fn redirect_is_off_origin(
    location: &str,
    request_host: &str,
    allowlist: &[&str],
) -> bool {
    let Some(host) = extract_redirect_host(location) else {
        // No host component (relative path) → same-origin → safe.
        return false;
    };
    let host_lower = host.to_ascii_lowercase();
    if !request_host.is_empty()
        && host_lower == request_host.trim().to_ascii_lowercase()
    {
        return false;
    }
    !allowlist
        .iter()
        .any(|h| host_lower == h.trim().to_ascii_lowercase())
}

/// Extract the host component from a `Location:` value.  Returns
/// `None` for a relative path (no scheme, no leading `//`).
///
/// Recognises three shapes:
/// 1. `scheme://host/path` — yields `host`.
/// 2. `//host/path` (schemeless / protocol-relative) — yields `host`.
/// 3. `/path` or `path` — yields `None` (same-origin).
fn extract_redirect_host(location: &str) -> Option<String> {
    let trimmed = location.trim();
    if trimmed.is_empty() {
        return None;
    }
    let rest = if let Some(after_scheme) = trimmed.find("://") {
        &trimmed[after_scheme + 3..]
    } else if let Some(stripped) = trimmed.strip_prefix("//") {
        stripped
    } else {
        return None;
    };
    // Strip path / query / fragment from the host segment.
    let end = rest
        .find(|c: char| matches!(c, '/' | '?' | '#'))
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    // Strip userinfo + port.  Bracketed IPv6 authorities (`[::1]` or
    // `[::1]:8080`) must keep the brackets together — splitting on the
    // last `:` inside the literal would slice the address apart.
    let after_userinfo = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host_only = if let Some(rest) = after_userinfo.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => &after_userinfo[..end + 2],
            None => after_userinfo,
        }
    } else {
        after_userinfo
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(after_userinfo)
    };
    let h = host_only.trim();
    if h.is_empty() {
        None
    } else {
        Some(h.to_owned())
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
        // Cross-cutting predicates; not evaluable against a single probe.
        // [`oracle_fired_with_stubs`] handles them via the partition path.
        ProbePredicate::StubEventMatches { .. }
        | ProbePredicate::DeserializeGadgetInvoked { .. }
        | ProbePredicate::TemplateEvalEqual { .. }
        | ProbePredicate::XxeEntityExpanded { .. }
        | ProbePredicate::QueryResultCountGreaterThan { .. }
        | ProbePredicate::HeaderInjected { .. }
        | ProbePredicate::RedirectHostNotIn { .. } => true,
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
    match &probe.kind {
        ProbeKind::Crash { signal } => Some(*signal),
        ProbeKind::Normal
        | ProbeKind::Deserialize { .. }
        | ProbeKind::Xxe { .. }
        | ProbeKind::Ldap { .. }
        | ProbeKind::Xpath { .. }
        | ProbeKind::HeaderEmit { .. }
        | ProbeKind::Redirect { .. } => None,
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
            hardening_outcome: None,
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
    fn template_eval_equal_fires_on_matching_render_json() {
        let mut o = outcome();
        o.stdout = br#"{"render":"49"}"#.to_vec();
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        };
        assert!(oracle_fired(&oracle, &o, &[]));
    }

    #[test]
    fn template_eval_equal_ignores_non_matching_render() {
        let mut o = outcome();
        o.stdout = br#"{"render":"7*7"}"#.to_vec();
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        };
        assert!(!oracle_fired(&oracle, &o, &[]));
    }

    #[test]
    fn template_eval_equal_returns_false_when_stdout_empty() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        };
        assert!(!oracle_fired(&oracle, &outcome(), &[]));
    }

    #[test]
    fn template_eval_equal_skips_non_json_lines() {
        let mut o = outcome();
        o.stdout = b"warning: hello\n{\"render\":\"49\"}\n".to_vec();
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        };
        assert!(oracle_fired(&oracle, &o, &[]));
    }

    fn redirect_probe(location: &str, request_host: &str) -> SinkProbe {
        SinkProbe {
            sink_callee: "HttpServletResponse.sendRedirect".into(),
            args: vec![],
            captured_at_ns: 1,
            payload_id: "phase09".into(),
            kind: ProbeKind::Redirect {
                location: location.into(),
                request_host: request_host.into(),
            },
            witness: ProbeWitness::empty(),
        }
    }

    #[test]
    fn redirect_off_origin_fires_when_host_outside_allowlist() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: &["example.com", "www.example.com"],
            }],
        };
        let probes = vec![redirect_probe("https://attacker.test/", "example.com")];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn redirect_off_origin_clears_on_same_origin_path() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: &["example.com"],
            }],
        };
        let probes = vec![redirect_probe("/dashboard", "example.com")];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn redirect_off_origin_clears_on_allowlisted_host() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: &["example.com", "cdn.example.com"],
            }],
        };
        let probes = vec![redirect_probe("https://cdn.example.com/asset", "example.com")];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn redirect_off_origin_clears_when_host_matches_request_host() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn { allowlist: &[] }],
        };
        let probes = vec![redirect_probe("https://example.com/dashboard", "example.com")];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn redirect_off_origin_fires_on_schemeless_authority() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: &["example.com"],
            }],
        };
        let probes = vec![redirect_probe("//attacker.test/path", "example.com")];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn redirect_off_origin_ignores_unrelated_probes() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: &["example.com"],
            }],
        };
        let probes = vec![probe("noop", vec![])];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn extract_redirect_host_handles_authority_variants() {
        assert_eq!(
            extract_redirect_host("https://attacker.test/path"),
            Some("attacker.test".to_owned()),
        );
        assert_eq!(
            extract_redirect_host("//attacker.test:8080/path"),
            Some("attacker.test".to_owned()),
        );
        assert_eq!(
            extract_redirect_host("https://user:pass@evil.example/?q=1"),
            Some("evil.example".to_owned()),
        );
        assert_eq!(extract_redirect_host("/dashboard"), None);
        assert_eq!(extract_redirect_host(""), None);
        // IPv6 bracketed authorities — host literal must keep brackets
        // and not be split on the colons inside the address.
        assert_eq!(
            extract_redirect_host("https://[::1]/path"),
            Some("[::1]".to_owned()),
        );
        assert_eq!(
            extract_redirect_host("https://[::1]:8080/path"),
            Some("[::1]".to_owned()),
        );
        assert_eq!(
            extract_redirect_host("https://[2001:db8::1]/x"),
            Some("[2001:db8::1]".to_owned()),
        );
        assert_eq!(
            extract_redirect_host("//[fe80::1]:443/y"),
            Some("[fe80::1]".to_owned()),
        );
        // IPv6 literal in allowlist round-trips through the off-origin
        // check now that the host fragment is well-formed.
        assert!(!redirect_is_off_origin(
            "https://[::1]/admin",
            "example.com",
            &["[::1]"],
        ));
        assert!(redirect_is_off_origin(
            "https://[2001:db8::dead]/x",
            "example.com",
            &["[::1]"],
        ));
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
