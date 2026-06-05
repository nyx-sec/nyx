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
    /// Phase 08 (Track J.6): wire-frame header-smuggling predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::HeaderWireFrame`] whose `raw_bytes` contains two
    /// distinct header lines on the wire — one starting with
    /// `primary:` and a separate line starting with `smuggled:`.
    /// Both names are matched case-insensitively against the leading
    /// token of each `\r\n`-terminated header line.
    ///
    /// Distinct from [`Self::HeaderInjected`], which fires on a
    /// single in-process `HeaderEmit` whose value contains a literal
    /// CRLF pair: a vulnerable host process can pass `\r\n`-bearing
    /// bytes into its framework's header setter *and* the framework
    /// can then CRLF-strip the bytes on the way to the wire, leaving
    /// the in-process probe satisfied but the actual response frame
    /// clean.  This predicate proves the smuggled header survived to
    /// the underlying server's response socket.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] /
    /// [`Self::HeaderInjected`] — evaluated across every drained
    /// probe rather than against a single record.
    HeaderSmuggledInWire {
        /// Header name the original payload set legitimately (e.g.
        /// `"Set-Cookie"`).  Must appear as the leading token of at
        /// least one `\r\n`-terminated wire line.
        primary: &'static str,
        /// Header name the attacker smuggled past the CRLF boundary
        /// (e.g. `"X-Injected"`).  Must appear as the leading token
        /// of a separate `\r\n`-terminated wire line.
        smuggled: &'static str,
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
    /// Phase 10 (Track J.8): prototype-pollution canary predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::PrototypePollution`] whose `property` matches
    /// `canary` (defaults to `"__nyx_canary"`).  The Node harness
    /// installs a `Proxy`-style setter trap on
    /// `Object.prototype.__nyx_canary`; any deep-merge / `Object.assign`
    /// / `JSON.parse`-then-deep-assign sink that walks an
    /// attacker-controlled `__proto__` key into the prototype chain
    /// trips the trap and writes a `PrototypePollution` probe.  A
    /// benign payload whose object literal has no `__proto__` key, or
    /// whose target is constructed via `Object.create(null)`, never
    /// reaches the canary so the predicate stays clear.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] /
    /// [`Self::HeaderInjected`] /
    /// [`Self::RedirectHostNotIn`] — evaluated across every drained
    /// probe rather than against a single record.
    PrototypeCanaryTouched {
        /// Canary property name, compared case-sensitively against
        /// [`ProbeKind::PrototypePollution::property`].
        ///
        /// The const corpus stores only [`Canary::PLACEHOLDER`] here; at
        /// run time [`oracle_fired_full`] is handed the per-spec
        /// [`Canary`] the runner substituted into the payload bytes and
        /// the harness's `NYX_CANARY` environment, and matches against
        /// that instead — so this field is the low-entropy placeholder,
        /// never the value actually compared in production.
        canary: &'static str,
    },
    /// Phase 11 (Track J.9): CRYPTO weak-key entropy predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::WeakKey`] whose `key_int` is strictly less than
    /// `2^max_bits` — i.e. the produced key actually fits inside the
    /// search-space budget the predicate models.  A benign control
    /// generated by a cryptographically strong RNG produces a
    /// `key_int` whose magnitude trivially exceeds the budget, so the
    /// predicate stays clear.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] — evaluated across every drained
    /// probe rather than against a single record.
    WeakKeyEntropy {
        /// Maximum effective-entropy budget (in bits) the produced
        /// key may consume before the oracle fires.  16 matches the
        /// brief's "fits in a 16-bit search space" oracle.
        max_bits: u32,
    },
    /// Phase 11 (Track J.9): UNAUTHORIZED_ID IDOR boundary predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::IdorAccess`] whose `caller_id` differs from
    /// `owner_id`.  Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] — evaluated across every drained
    /// probe rather than against a single record.
    IdorBoundaryCrossed,
    /// Phase 11 (Track J.9): DATA_EXFIL outbound-host predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::OutboundNetwork`] whose `host` falls outside the
    /// `allowlist`.  Hosts are compared case-insensitively; the
    /// canonical allowlist for benign controls is `&["127.0.0.1",
    /// "localhost"]` so a vulnerable host that exfiltrates to
    /// `attacker.test` resolves off-list and confirms.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] — evaluated across every drained
    /// probe rather than against a single record.
    OutboundHostNotIn {
        /// Allowlist of permitted egress hosts (e.g.
        /// `&["127.0.0.1", "localhost"]`).  A probe whose `host`
        /// matches any entry is treated as same-origin.
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
    /// Phase 11 (Track J.9): JSON_PARSE depth-bomb predicate.
    ///
    /// Fires when at least one drained probe carries
    /// [`ProbeKind::JsonParse`] whose `depth > max_depth` OR whose
    /// `excessive_depth` flag is set.  The canonical attacker payload
    /// is a deeply-nested JSON document (`[[[[[...]]]]]`) that drives
    /// the host's parser to a recursion limit or stack-exhaustion
    /// shape; the benign control is a flat or shallowly-nested
    /// document that leaves the predicate clear.
    ///
    /// Cross-cutting in the same sense as
    /// [`Self::DeserializeGadgetInvoked`] /
    /// [`Self::XxeEntityExpanded`] — evaluated across every drained
    /// probe rather than against a single record.
    JsonParseExcessiveDepth {
        /// Maximum legal nesting depth.  A captured probe with
        /// `depth > max_depth` (or `excessive_depth = true`) fires the
        /// predicate.  Typical benign depths are under 8; depth-bomb
        /// payloads ship 256+ nested arrays.
        max_depth: u32,
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
    SinkProbe {
        predicates: &'static [ProbePredicate],
    },
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
///
/// Thin wrapper over [`oracle_fired_full`] with no per-spec canary —
/// every [`ProbePredicate::PrototypeCanaryTouched`] matches against the
/// const corpus's stored [`Canary::PLACEHOLDER`] token.  Production
/// callers in the runner use [`oracle_fired_full`] with the per-spec
/// canary; this entry point is preserved for tests and pre-Phase-30
/// callers.
pub fn oracle_fired_with_stubs(
    oracle: &Oracle,
    outcome: &SandboxOutcome,
    probes: &[SinkProbe],
    stub_events: &[StubEvent],
) -> bool {
    oracle_fired_full(oracle, outcome, probes, stub_events, None)
}

/// Phase 30 (Track N.0): evaluate an oracle with the per-spec
/// verification [`Canary`] threaded in.
///
/// When `canary` is `Some`, every
/// [`ProbePredicate::PrototypeCanaryTouched`] matches the drained probe's
/// `property` against the runtime canary the runner derived from the
/// finding's `spec_hash` and substituted into the payload bytes + the
/// harness's `NYX_CANARY` environment — rather than the const corpus's
/// low-entropy [`Canary::PLACEHOLDER`] token.  Keying the match on a
/// per-spec value means a probe record left over from one finding's run
/// (or ambient harness output that happens to mention the historical
/// `__nyx_canary` sentinel) can never satisfy a different finding's
/// oracle.  `None` keeps the placeholder-match path for unit tests and
/// any caller that has not derived a per-spec canary.
#[allow(deprecated)]
pub fn oracle_fired_full(
    oracle: &Oracle,
    outcome: &SandboxOutcome,
    probes: &[SinkProbe],
    stub_events: &[StubEvent],
    canary: Option<&str>,
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
            // Phase 08 (Track J.6): wire-frame header-smuggling
            // cross-cutting predicates.  Each
            // `HeaderSmuggledInWire { primary, smuggled }` consults
            // the captured probe channel for a
            // [`ProbeKind::HeaderWireFrame`] record whose `raw_bytes`
            // contain two distinct `name:` lines.
            let header_wire_ok = cross.iter().all(|p| match p {
                ProbePredicate::HeaderSmuggledInWire { primary, smuggled } => {
                    probes_satisfy_header_smuggled_in_wire(probes, primary, smuggled)
                }
                _ => true,
            });
            if !header_wire_ok {
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
            // Phase 10 (Track J.8): prototype-pollution canary
            // cross-cutting predicates.  Each
            // `PrototypeCanaryTouched { canary }` consults the
            // captured probe channel for a
            // [`ProbeKind::PrototypePollution`] record whose
            // `property` matches the canary name.
            let canary_ok = cross.iter().all(|p| match p {
                ProbePredicate::PrototypeCanaryTouched {
                    canary: placeholder,
                } => probes_satisfy_prototype_canary(probes, canary.unwrap_or(placeholder)),
                _ => true,
            });
            if !canary_ok {
                return false;
            }
            // Phase 11 (Track J.9): CRYPTO weak-key, UNAUTHORIZED_ID
            // IDOR, DATA_EXFIL outbound-host cross-cutting predicates.
            let weak_key_ok = cross.iter().all(|p| match p {
                ProbePredicate::WeakKeyEntropy { max_bits } => {
                    probes_satisfy_weak_key(probes, *max_bits)
                }
                _ => true,
            });
            if !weak_key_ok {
                return false;
            }
            let idor_ok = cross.iter().all(|p| match p {
                ProbePredicate::IdorBoundaryCrossed => probes_satisfy_idor_crossed(probes),
                _ => true,
            });
            if !idor_ok {
                return false;
            }
            let outbound_ok = cross.iter().all(|p| match p {
                ProbePredicate::OutboundHostNotIn { allowlist } => {
                    probes_satisfy_outbound_off_list(probes, allowlist)
                }
                _ => true,
            });
            if !outbound_ok {
                return false;
            }
            // Phase 11 (Track J.9): JSON_PARSE depth-bomb cross-cutting
            // predicates.  Each `JsonParseExcessiveDepth { max_depth }`
            // consults the captured probe channel for a
            // [`ProbeKind::JsonParse`] record whose `depth > max_depth`
            // OR whose `excessive_depth` flag is set.
            let json_parse_ok = cross.iter().all(|p| match p {
                ProbePredicate::JsonParseExcessiveDepth { max_depth } => {
                    probes_satisfy_json_parse_excessive(probes, *max_depth)
                }
                _ => true,
            });
            if !json_parse_ok {
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
            | ProbeKind::HeaderWireFrame { .. }
            | ProbeKind::Redirect { .. }
            | ProbeKind::PrototypePollution { .. }
            | ProbeKind::WeakKey { .. }
            | ProbeKind::IdorAccess { .. }
            | ProbeKind::OutboundNetwork { .. }
            | ProbeKind::JsonParse { .. } => false,
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
            | ProbePredicate::HeaderSmuggledInWire { .. }
            | ProbePredicate::RedirectHostNotIn { .. }
            | ProbePredicate::PrototypeCanaryTouched { .. }
            | ProbePredicate::WeakKeyEntropy { .. }
            | ProbePredicate::IdorBoundaryCrossed
            | ProbePredicate::OutboundHostNotIn { .. }
            | ProbePredicate::JsonParseExcessiveDepth { .. }
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
        // HeaderSmuggledInWire is cross-cutting against the
        // *probe log* rather than stub events; evaluated
        // separately in [`probes_satisfy_header_smuggled_in_wire`]
        // below.
        ProbePredicate::HeaderSmuggledInWire { .. } => true,
        // RedirectHostNotIn is cross-cutting against the *probe log*
        // rather than stub events; evaluated separately in
        // [`probes_satisfy_redirect_off_origin`] below.
        ProbePredicate::RedirectHostNotIn { .. } => true,
        // PrototypeCanaryTouched is cross-cutting against the *probe
        // log* rather than stub events; evaluated separately in
        // [`probes_satisfy_prototype_canary`] below.
        ProbePredicate::PrototypeCanaryTouched { .. } => true,
        // Phase 11 (Track J.9) cross-cutters are all probe-log
        // backed and evaluated by their dedicated helpers below.
        ProbePredicate::WeakKeyEntropy { .. } => true,
        ProbePredicate::IdorBoundaryCrossed => true,
        ProbePredicate::OutboundHostNotIn { .. } => true,
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
        let Some(render) = v.get("render") else {
            continue;
        };
        let Some(s) = render.as_str() else { continue };
        if let Ok(n) = s.trim().parse::<u64>()
            && n == expected
        {
            return true;
        }
    }
    false
}

/// True when at least one drained probe is a
/// [`ProbeKind::Deserialize`] record matching `require_invoked`.
fn probes_satisfy_deserialize(probes: &[SinkProbe], require_invoked: bool) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::Deserialize {
            gadget_chain_invoked,
        } => *gadget_chain_invoked == require_invoked,
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
        ProbeKind::HeaderEmit { name, value, .. } => {
            (header_name == "*" || name.eq_ignore_ascii_case(header_name)) && value.contains("\r\n")
        }
        _ => false,
    })
}

/// True when at least one drained probe is a
/// [`ProbeKind::HeaderWireFrame`] whose `raw_bytes` carries two
/// distinct `\r\n`-terminated header lines whose leading tokens
/// (everything before the first `:`) match `primary` and `smuggled`
/// case-insensitively.  Powers
/// [`ProbePredicate::HeaderSmuggledInWire`] (Phase 08 — Track J.6).
///
/// Same line must not satisfy both names; the predicate models two
/// independent header lines, not a single line whose value happens
/// to contain a `:` substring.
fn probes_satisfy_header_smuggled_in_wire(
    probes: &[SinkProbe],
    primary: &str,
    smuggled: &str,
) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::HeaderWireFrame { raw_bytes } => {
            wire_frame_has_distinct_header_lines(raw_bytes, primary, smuggled)
        }
        _ => false,
    })
}

/// Returns `true` when `bytes` contains a `\r\n`-terminated line
/// whose leading `name:` token matches `primary` (case-insensitive)
/// *and* a separate `\r\n`-terminated line whose leading `name:`
/// token matches `smuggled`.  The two matches must come from
/// distinct lines.  Lines without a `:` are skipped.
///
/// Used by [`probes_satisfy_header_smuggled_in_wire`]; pulled out so
/// the colocated tests can exercise the wire-byte scan directly.
pub(crate) fn wire_frame_has_distinct_header_lines(
    bytes: &[u8],
    primary: &str,
    smuggled: &str,
) -> bool {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let primary_lower = primary.trim().to_ascii_lowercase();
    let smuggled_lower = smuggled.trim().to_ascii_lowercase();
    if primary_lower.is_empty() || smuggled_lower.is_empty() {
        return false;
    }
    let mut saw_primary = false;
    let mut saw_smuggled = false;
    for line in text.split("\r\n") {
        let Some(colon) = line.find(':') else {
            continue;
        };
        let name = line[..colon].trim().to_ascii_lowercase();
        if !saw_primary && name == primary_lower {
            saw_primary = true;
            continue;
        }
        if !saw_smuggled && name == smuggled_lower {
            saw_smuggled = true;
        }
    }
    saw_primary && saw_smuggled
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
        ProbeKind::Redirect {
            location,
            request_host,
        } => redirect_is_off_origin(location, request_host, allowlist),
        _ => false,
    })
}

/// True when at least one drained probe is a
/// [`ProbeKind::PrototypePollution`] record whose `property` matches
/// `canary`.  Powers
/// [`ProbePredicate::PrototypeCanaryTouched`] (Phase 10 — Track J.8).
fn probes_satisfy_prototype_canary(probes: &[SinkProbe], canary: &str) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::PrototypePollution { property, .. } => property == canary,
        _ => false,
    })
}

/// True when at least one drained probe is a [`ProbeKind::WeakKey`]
/// record whose `key_int` is strictly less than `2^max_bits`.  Powers
/// [`ProbePredicate::WeakKeyEntropy`] (Phase 11 — Track J.9).
///
/// `max_bits >= 64` is treated as "never fires" — a 64-bit key
/// trivially exceeds any sub-search-space budget once you cap the
/// integer view at `u64`.  The brief calls for a 16-bit search-space
/// oracle, so the real threshold sits far below `2^64`.
fn probes_satisfy_weak_key(probes: &[SinkProbe], max_bits: u32) -> bool {
    if max_bits == 0 {
        return false;
    }
    if max_bits >= 64 {
        return probes
            .iter()
            .any(|p| matches!(p.kind, ProbeKind::WeakKey { .. }));
    }
    let budget = 1u64 << max_bits;
    probes.iter().any(|p| match &p.kind {
        ProbeKind::WeakKey { key_int } => *key_int < budget,
        _ => false,
    })
}

/// True when at least one drained probe is a
/// [`ProbeKind::IdorAccess`] record whose `caller_id` differs from
/// `owner_id`.  Powers
/// [`ProbePredicate::IdorBoundaryCrossed`] (Phase 11 — Track J.9).
fn probes_satisfy_idor_crossed(probes: &[SinkProbe]) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::IdorAccess {
            caller_id,
            owner_id,
        } => caller_id != owner_id,
        _ => false,
    })
}

/// True when at least one drained probe is a
/// [`ProbeKind::OutboundNetwork`] record whose `host` falls outside
/// `allowlist` (case-insensitive).  Powers
/// [`ProbePredicate::OutboundHostNotIn`] (Phase 11 — Track J.9).
fn probes_satisfy_outbound_off_list(probes: &[SinkProbe], allowlist: &[&str]) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::OutboundNetwork { host } => {
            let h = host.trim().to_ascii_lowercase();
            if h.is_empty() {
                return false;
            }
            !allowlist.iter().any(|a| h == a.trim().to_ascii_lowercase())
        }
        _ => false,
    })
}

/// True when at least one drained probe is a
/// [`ProbeKind::JsonParse`] record whose `depth > max_depth` OR whose
/// `excessive_depth` flag is set.  Powers
/// [`ProbePredicate::JsonParseExcessiveDepth`] (Phase 11 — Track J.9).
///
/// `excessive_depth` short-circuits — a shim that already caught the
/// parser's own recursion-limit signal can emit
/// `JsonParse { depth: 0, excessive_depth: true }` without counting
/// nesting manually and still trip the predicate.
fn probes_satisfy_json_parse_excessive(probes: &[SinkProbe], max_depth: u32) -> bool {
    probes.iter().any(|p| match &p.kind {
        ProbeKind::JsonParse {
            depth,
            excessive_depth,
        } => *excessive_depth || *depth > max_depth,
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
    if !request_host.is_empty() && host_lower == request_host.trim().to_ascii_lowercase() {
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
    } else {
        trimmed.strip_prefix("//")?
    };
    // Strip path / query / fragment from the host segment.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // Strip userinfo + port.  Bracketed IPv6 authorities (`[::1]` or
    // `[::1]:8080`) must keep the brackets together — splitting on the
    // last `:` inside the literal would slice the address apart.
    let after_userinfo = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
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
        | ProbePredicate::HeaderSmuggledInWire { .. }
        | ProbePredicate::RedirectHostNotIn { .. }
        | ProbePredicate::PrototypeCanaryTouched { .. }
        | ProbePredicate::WeakKeyEntropy { .. }
        | ProbePredicate::IdorBoundaryCrossed
        | ProbePredicate::OutboundHostNotIn { .. }
        | ProbePredicate::JsonParseExcessiveDepth { .. } => true,
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
        | ProbeKind::HeaderWireFrame { .. }
        | ProbeKind::Redirect { .. }
        | ProbeKind::PrototypePollution { .. }
        | ProbeKind::WeakKey { .. }
        | ProbeKind::IdorAccess { .. }
        | ProbeKind::OutboundNetwork { .. }
        | ProbeKind::JsonParse { .. } => None,
    }
}

/// Per-spec verification canary (Phase 30 — Track N.0).
///
/// Tracks J.1–J.9 (phases 03–11) seeded their probe-based oracles with a
/// single fixed sentinel string, `__nyx_canary`: the *same* low-entropy
/// token appeared in every spec's payload bytes, every prototype-pollution
/// harness's setter trap, and every
/// [`ProbePredicate::PrototypeCanaryTouched`] in the const corpus.  A fixed
/// token is wrong on three counts the plan calls out: it is (a) not
/// cryptographically random, (b) not collision-resistant against ambient
/// harness output (anything that prints `__nyx_canary` matches), and (c) not
/// per-spec — a probe record left in a reused workdir from one finding's run
/// could satisfy a different finding's oracle.
///
/// `Canary` replaces it with a value derived per finding from the finding's
/// [`spec_hash`](crate::dynamic::spec::HarnessSpec::spec_hash) and a
/// process-global run nonce.  The const corpus carries only the
/// [`PLACEHOLDER`](Canary::PLACEHOLDER) token; the runner computes the real
/// canary once per spec via [`generate`](Canary::generate) +
/// [`render`](Canary::render) and substitutes it into (1) the payload bytes,
/// (2) the harness's `NYX_CANARY` environment variable, and (3) the oracle
/// match (threaded through [`oracle_fired_full`]).  All three agree on the
/// same per-spec value at run time while the corpus source stays
/// `const`-declarable.
///
/// The verdict never depends on the canary's *value* — only on whether the
/// pollution reached it — so deriving it from a fresh run nonce does not
/// break the engine's rerun-determinism contract (identical inputs still
/// produce identical verdicts).
pub struct Canary;

impl Canary {
    /// Placeholder token embedded in the const corpus: payload byte
    /// literals, the `canary` field of
    /// [`ProbePredicate::PrototypeCanaryTouched`], and the per-language
    /// harness's `NYX_CANARY` fallback.  Substituted with a per-spec
    /// [`render`](Canary::render)ed value at run time.
    ///
    /// Kept byte-for-byte equal to the historical `__nyx_canary` sentinel so
    /// legacy fixtures, the harness env fallback, and the colocated unit
    /// tests that exercise the placeholder-match path keep resolving.  The
    /// Phase 30 audit (`tests/oracle_canary_audit.rs`) asserts every
    /// canary-bearing predicate in the corpus uses exactly this constant, so
    /// a new ad-hoc literal fails the build.
    pub const PLACEHOLDER: &'static str = "__nyx_canary";

    /// Bits of entropy a [`render`](Canary::render)ed canary carries.
    ///
    /// [`generate`](Canary::generate) returns 32 bytes and `render` encodes
    /// every byte, so a rendered canary is 256 bits — comfortably above the
    /// 128-bit floor the Phase 30 audit enforces.
    pub const ENTROPY_BITS: u32 = 256;

    /// Derive a 32-byte canary for the finding identified by `spec_hash`.
    ///
    /// `BLAKE3("nyx.dynamic.canary.v1" ‖ run_nonce ‖ spec_hash)`.  The
    /// `run_nonce` is a process-global value seeded once from the OS
    /// CSPRNG (mixed with time + pid as a fallback), so two runs of the same
    /// spec draw different canaries and a stale probe record cannot satisfy a
    /// later run.  Keying on `spec_hash` gives every finding in a single run
    /// a distinct canary, so one finding's canary can never collide with
    /// another's.  Deterministic within a process — the audit relies on this.
    pub fn generate(spec_hash: &str) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"nyx.dynamic.canary.v1\0");
        h.update(&run_nonce());
        h.update(b"\0");
        h.update(spec_hash.as_bytes());
        *h.finalize().as_bytes()
    }

    /// Render a generated canary as a 64-character lowercase-hex token.
    ///
    /// Hex keeps the canary safe to embed verbatim as a JSON object key, a
    /// JavaScript property name, and a header / filter token without
    /// escaping.  Every byte is encoded, so the token carries the full
    /// [`ENTROPY_BITS`](Canary::ENTROPY_BITS).
    pub fn render(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }

    /// Convenience: the per-spec canary already rendered to its run-time
    /// string form.  Equivalent to `render(&generate(spec_hash))`.
    pub fn for_spec(spec_hash: &str) -> String {
        Self::render(&Self::generate(spec_hash))
    }
}

/// Process-global run nonce backing [`Canary::generate`].
///
/// Seeded once, lazily, from the OS CSPRNG (`/dev/urandom` on Unix) mixed
/// with the wall clock, pid, and a counter so the value is fresh per process
/// but stable within it.  The fallback mixing guarantees a non-repeating seed
/// even when no CSPRNG source is reachable.
fn run_nonce() -> [u8; 32] {
    use std::sync::OnceLock;
    static RUN_NONCE: OnceLock<[u8; 32]> = OnceLock::new();
    *RUN_NONCE.get_or_init(|| {
        let mut h = blake3::Hasher::new();
        h.update(b"nyx.dynamic.run_nonce.v1\0");
        let mut os = [0u8; 32];
        if read_os_entropy(&mut os) {
            h.update(&os);
        }
        // Always mix time + pid + a counter so a missing or blocked CSPRNG
        // still yields a fresh, non-repeating seed.
        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            h.update(&d.as_nanos().to_le_bytes());
        }
        h.update(&(std::process::id() as u64).to_le_bytes());
        static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let c = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        h.update(&c.to_le_bytes());
        *h.finalize().as_bytes()
    })
}

/// Fill `buf` from the OS CSPRNG.  Returns `false` (caller falls back to the
/// time + pid mixing) when no source is available on the platform.
#[cfg_attr(not(unix), allow(unused_variables))]
fn read_os_entropy(buf: &mut [u8]) -> bool {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            return f.read_exact(buf).is_ok();
        }
    }
    false
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
                ProbePredicate::ArgContains {
                    index: 0,
                    needle: "; echo",
                },
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
                ProbePredicate::ArgContains {
                    index: 0,
                    needle: "NEVER_PRESENT",
                },
            ],
        };
        let probes = vec![probe("os.system", vec![ProbeArg::String("hello".into())])];
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
            predicates: &[ProbePredicate::ArgEquals {
                index: 0,
                value: "exact",
            }],
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
        let probes = vec![redirect_probe(
            "https://cdn.example.com/asset",
            "example.com",
        )];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn redirect_off_origin_clears_when_host_matches_request_host() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn { allowlist: &[] }],
        };
        let probes = vec![redirect_probe(
            "https://example.com/dashboard",
            "example.com",
        )];
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

    fn prototype_pollution_probe(property: &str, value: &str) -> SinkProbe {
        SinkProbe {
            sink_callee: "__nyx_pp_canary_set".into(),
            args: vec![],
            captured_at_ns: 1,
            payload_id: "phase10".into(),
            kind: ProbeKind::PrototypePollution {
                property: property.into(),
                value: value.into(),
            },
            witness: ProbeWitness::empty(),
        }
    }

    #[test]
    fn prototype_canary_touched_fires_on_matching_property() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched {
                canary: "__nyx_canary",
            }],
        };
        let probes = vec![prototype_pollution_probe("__nyx_canary", "pwned")];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn prototype_canary_touched_ignores_mismatched_property() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched {
                canary: "__nyx_canary",
            }],
        };
        let probes = vec![prototype_pollution_probe("__other__", "x")];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn prototype_canary_touched_clears_when_no_pp_probe() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched {
                canary: "__nyx_canary",
            }],
        };
        let probes = vec![probe("noop", vec![])];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    fn header_emit_probe(name: &str, value: &str) -> SinkProbe {
        SinkProbe {
            sink_callee: "HttpServletResponse.setHeader".into(),
            args: vec![],
            captured_at_ns: 1,
            payload_id: "phase08".into(),
            kind: ProbeKind::HeaderEmit {
                name: name.into(),
                value: value.into(),
                protocol: crate::dynamic::probe::HeaderEmitProtocol::InProcess,
            },
            witness: ProbeWitness::empty(),
        }
    }

    fn header_wire_probe(raw: &[u8]) -> SinkProbe {
        SinkProbe {
            sink_callee: "wire-tap".into(),
            args: vec![],
            captured_at_ns: 1,
            payload_id: "phase08-wire".into(),
            kind: ProbeKind::HeaderWireFrame {
                raw_bytes: raw.to_vec(),
            },
            witness: ProbeWitness::empty(),
        }
    }

    #[test]
    fn header_smuggled_in_wire_fires_on_two_distinct_header_lines() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderSmuggledInWire {
                primary: "Set-Cookie",
                smuggled: "X-Injected",
            }],
        };
        let probes = vec![header_wire_probe(b"Set-Cookie: a=1\r\nX-Injected: 1\r\n")];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn header_smuggled_in_wire_clears_when_only_primary_line_present() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderSmuggledInWire {
                primary: "Set-Cookie",
                smuggled: "X-Injected",
            }],
        };
        // Benign control: framework URL-encoded the CRLF on the way
        // to the wire, leaving the original Set-Cookie intact and no
        // sibling X-Injected line.
        let probes = vec![header_wire_probe(
            b"Set-Cookie: a=1%0d%0aX-Injected:%201\r\n",
        )];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn header_smuggled_in_wire_matches_case_insensitively() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderSmuggledInWire {
                primary: "set-cookie",
                smuggled: "x-injected",
            }],
        };
        let probes = vec![header_wire_probe(b"SET-COOKIE: a=1\r\nX-INJECTED: 1\r\n")];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn header_smuggled_in_wire_ignores_header_emit_probes() {
        // A tier-(a) HeaderEmit probe whose value carries `\r\n`
        // satisfies HeaderInjected but must not satisfy
        // HeaderSmuggledInWire — that predicate proves the bytes
        // survived to the response socket.
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderSmuggledInWire {
                primary: "Set-Cookie",
                smuggled: "X-Injected",
            }],
        };
        let probes = vec![header_emit_probe("Set-Cookie", "a=1\r\nX-Injected: 1")];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn header_injected_ignores_header_wire_frame_probes() {
        // Symmetric: the existing HeaderInjected predicate must keep
        // ignoring wire-frame probes — those only satisfy the new
        // wire-smuggling predicate.
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        };
        let probes = vec![header_wire_probe(b"Set-Cookie: a=1\r\nX-Injected: 1\r\n")];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn wire_frame_helper_handles_repeated_primary_name_via_self_smuggling() {
        // Classic CRLF smuggling attack: attacker injects a second
        // `Set-Cookie` line by tunnelling through the original.  The
        // helper accepts same-name twice as proof when `primary`
        // and `smuggled` are configured to the same name.
        assert!(wire_frame_has_distinct_header_lines(
            b"Set-Cookie: original=1\r\nSet-Cookie: attacker=1\r\n",
            "Set-Cookie",
            "Set-Cookie",
        ));
    }

    #[test]
    fn wire_frame_helper_rejects_single_line_with_inline_colon_value() {
        // A line like `Set-Cookie: foo=bar; ext=baz` contains a `:`
        // in the value segment but only one true header line; the
        // helper splits on `\r\n` so the value's `:` cannot satisfy
        // the smuggled predicate by itself.
        assert!(!wire_frame_has_distinct_header_lines(
            b"Set-Cookie: foo=bar; ext=baz\r\n",
            "Set-Cookie",
            "X-Injected",
        ));
    }

    #[test]
    fn wire_frame_helper_rejects_non_utf8_bytes() {
        assert!(!wire_frame_has_distinct_header_lines(
            &[0xff, 0xfe, 0xfd],
            "Set-Cookie",
            "X-Injected",
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

    fn json_parse_probe(depth: u32, excessive_depth: bool) -> SinkProbe {
        SinkProbe {
            sink_callee: "json.loads".into(),
            args: vec![],
            captured_at_ns: 1,
            payload_id: "phase11-json".into(),
            kind: ProbeKind::JsonParse {
                depth,
                excessive_depth,
            },
            witness: ProbeWitness::empty(),
        }
    }

    #[test]
    fn json_parse_excessive_depth_fires_when_depth_exceeds_budget() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth { max_depth: 64 }],
        };
        let probes = vec![json_parse_probe(512, false)];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn json_parse_excessive_depth_fires_on_short_circuit_flag_even_with_zero_depth() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth { max_depth: 64 }],
        };
        // Shim caught the parser's own recursion limit and emitted
        // `excessive_depth: true` without counting nesting — predicate
        // should still fire.
        let probes = vec![json_parse_probe(0, true)];
        assert!(oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn json_parse_excessive_depth_clears_when_depth_within_budget() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth { max_depth: 64 }],
        };
        // Benign control: shallowly nested object.
        let probes = vec![json_parse_probe(3, false)];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    #[test]
    fn json_parse_excessive_depth_ignores_unrelated_probe_kinds() {
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth { max_depth: 64 }],
        };
        // A HeaderEmit probe (different kind) must not satisfy the
        // predicate even if the shim emitted both for the same payload.
        let probes = vec![header_emit_probe("Set-Cookie", "noise")];
        assert!(!oracle_fired(&oracle, &outcome(), &probes));
    }

    // ── Phase 30 (Track N.0): per-spec canary ───────────────────────────

    #[test]
    fn canary_generate_is_deterministic_within_process() {
        let a = Canary::generate("deadbeefcafe0001");
        let b = Canary::generate("deadbeefcafe0001");
        assert_eq!(a, b, "same spec_hash must yield the same canary in-process");
        assert_eq!(Canary::for_spec("h"), Canary::for_spec("h"));
    }

    #[test]
    fn canary_render_is_64_lowercase_hex() {
        let bytes = Canary::generate("spec-hash-xyz");
        assert_eq!(bytes.len(), 32, "canary is 32 bytes / 256 bits");
        let r = Canary::render(&bytes);
        assert_eq!(r.len(), 64, "render encodes every byte as two hex digits");
        assert!(
            r.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "render must be lowercase hex: {r}",
        );
        const { assert!(Canary::ENTROPY_BITS >= 128) };
        assert!(
            r.len() * 4 >= 128,
            "rendered canary clears the 128-bit floor"
        );
    }

    #[test]
    fn canary_distinct_spec_hashes_yield_distinct_canaries() {
        assert_ne!(Canary::for_spec("aaaa"), Canary::for_spec("bbbb"));
        // No collisions across a large sweep of distinct spec hashes:
        // distinct findings always get distinct canaries.
        let mut seen = std::collections::HashSet::new();
        for i in 0..4096u32 {
            let sh = format!("{i:016x}");
            assert!(
                seen.insert(Canary::for_spec(&sh)),
                "canary collision at spec_hash {sh}",
            );
        }
    }

    #[test]
    fn oracle_full_canary_override_matches_runtime_property_not_placeholder() {
        // The corpus predicate stores only the placeholder; the runner
        // supplies the per-spec canary.  A probe whose `property` is the
        // runtime canary must fire under the override and NOT under the
        // stale placeholder.
        let runtime = Canary::for_spec("phase30-spec");
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched {
                canary: Canary::PLACEHOLDER,
            }],
        };
        let probes = vec![prototype_pollution_probe(&runtime, "pwned")];
        // With the per-spec override: fires.
        assert!(oracle_fired_full(
            &oracle,
            &outcome(),
            &probes,
            &[],
            Some(&runtime),
        ));
        // Without an override (None): the predicate's placeholder does not
        // match the runtime property, so it does NOT fire — proving a
        // probe carrying the per-spec canary cannot satisfy a placeholder
        // match, and vice-versa.
        assert!(!oracle_fired_full(&oracle, &outcome(), &probes, &[], None));
    }

    #[test]
    fn oracle_full_canary_override_rejects_stale_placeholder_probe() {
        // A probe carrying the historical `__nyx_canary` sentinel (e.g.
        // left over from a pre-Phase-30 run or ambient output) must NOT
        // satisfy a run whose per-spec canary differs.
        let runtime = Canary::for_spec("phase30-spec-2");
        let oracle = Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched {
                canary: Canary::PLACEHOLDER,
            }],
        };
        let probes = vec![prototype_pollution_probe(Canary::PLACEHOLDER, "pwned")];
        assert!(!oracle_fired_full(
            &oracle,
            &outcome(),
            &probes,
            &[],
            Some(&runtime),
        ));
    }
}
