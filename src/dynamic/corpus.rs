// Legacy [`Oracle::OutputContains`] is intentionally retained for
// pre-Phase-06 corpus entries until they migrate to
// [`Oracle::SinkProbe`].  The deprecation warning is informational, not a
// signal to migrate inside this module.
#![allow(deprecated)]

//! Per-capability payload corpus, keyed by `(Cap, Lang)`.
//!
//! Each `(Cap, Lang)` pair maps to a small set of canonical payloads plus a
//! matching detection oracle.  Payloads are static data — adding a new one
//! is a code review, not a runtime config knob, so they cannot drift
//! between versions.
//!
//! Differential confirmation (§4.1): every non-benign payload either
//! references a paired benign control (resolved inside the same
//! `(cap, lang)` slice) or carries a written
//! [`CuratedPayload::no_benign_control_rationale`] explaining why no
//! control is meaningful.  The [`audit`] module enforces this both at
//! compile time and via the runtime `corpus_registry::audit` test.
//!
//! # Module layout
//!
//! ```text
//! corpus.rs                    — types, public re-exports, module root
//! corpus/registry.rs           — CapCorpus, CORPUS, payloads_for{,_lang}
//! corpus/audit.rs              — compile-time + runtime audits
//! corpus/<cap>/<lang>.rs       — per-(cap, lang) `pub const PAYLOADS`
//! ```
//!
//! Adding a new language for a cap means: drop a new file under
//! `corpus/<cap>/<lang>.rs`, register `pub mod <lang>;` in the cap's
//! `mod.rs`, and wire `(Cap::<CAP>, Lang::<Lang>, <cap>::<lang>::PAYLOADS)`
//! into [`registry::ENTRIES`].  No other file needs to change.
//!
//! # Corpus governance (§16.1)
//!
//! Every payload carries [`PayloadProvenance`], a [`since_corpus_version`],
//! and at least one [`fixture_paths`] entry.  The [`CORPUS_VERSION`] const
//! tracks the history of incompatible corpus changes; bumping it
//! invalidates all `dynamic_verdict_cache` entries whose spec touched the
//! changed cap.

use crate::dynamic::oracle::ProbePredicate;
use crate::labels::Cap;
use crate::symbol::Lang;

pub mod audit;
pub mod registry;

mod cmdi;
mod deserialize;
mod fmt_string;
mod path_trav;
mod sqli;
mod ssrf;
mod ssti;
mod xss;

pub use registry::{
    audit_marker_collisions, benign_payload_for, benign_payload_for_lang, materialise_bytes,
    payloads_for, payloads_for_lang, resolve_benign_control, resolve_benign_control_lang,
    CORPUS, CORPUS_UNSUPPORTED_LANG_NEUTRAL,
};

/// Re-exported canonical [`Oracle`] type.
///
/// The actual enum lives in [`crate::dynamic::oracle`] alongside
/// [`crate::dynamic::oracle::ProbePredicate`] and
/// [`crate::dynamic::oracle::oracle_fired`].  Re-exported here so the
/// `CuratedPayload.oracle: Oracle` field reads naturally and existing
/// `crate::dynamic::corpus::Oracle` callers keep working.
pub use crate::dynamic::oracle::Oracle;

/// Bump when the corpus content changes in a way that invalidates previously-
/// computed [`crate::dynamic::spec::HarnessSpec::spec_hash`] values.
///
/// # Bump history
///
/// | Version | Date       | Change                                        |
/// |---------|------------|-----------------------------------------------|
/// | 1       | 2025-11-01 | Initial corpus (SQLi, CMDI, PATH_TRAV, SSRF, XSS) |
/// | 2       | 2025-12-15 | SSRF OOB-variant added; oracle semantics tightened |
/// | 3       | 2026-05-12 | Migrated to `CuratedPayload`; provenance + fixture_paths enforced; SSRF OOB-nonce slot added |
/// | 4       | 2026-05-14 | Phase 07: `benign_control` paired refs + benign payloads added to SQLI / CMDI / SSRF (file-scheme) |
/// | 5       | 2026-05-16 | FMT_STRING SinkCrash payload + benign control (Phase 08 unrelated-crash acceptance fixture) |
/// | 6       | 2026-05-17 | Phase 02 / Track J.0: `(Cap, Lang)` registry refactor; `no_benign_control_rationale` field; compile-time provenance audit |
/// | 7       | 2026-05-17 | Phase 03 / Track J.1: `DESERIALIZE` cap lit for Java / Python / PHP / Ruby; `ProbeKind::Deserialize` + `ProbePredicate::DeserializeGadgetInvoked` |
/// | 8       | 2026-05-17 | Phase 04 / Track J.2: `SSTI` cap lit for Jinja2 / ERB / Twig / Thymeleaf / Handlebars; `ProbePredicate::TemplateEvalEqual` |
pub const CORPUS_VERSION: u32 = 8;

/// Where a payload originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadProvenance {
    /// Manually written and reviewed by the Nyx team.
    Curated,
    /// Produced by the internal mutation fuzzer (`fuzz/dynamic_corpus/`).
    /// Still requires human promotion review (§16.4) before landing here.
    InternalFuzzer,
    /// Derived from a public CVE or external security report.
    ExternalReport,
}

/// Reference from a vulnerable payload to its paired benign control.
///
/// Resolved at call time by scanning the same cap's payload slice for an
/// `is_benign == true` entry whose `label` matches.  Stored as `&'static
/// str` (rather than a back-pointer to [`CuratedPayload`]) so the corpus
/// tables stay `const`-declarable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadRef {
    /// Label of the benign-control entry inside the same cap's payload set.
    pub label: &'static str,
}

/// A single payload entry in the curated corpus.
///
/// Governs both static payload bytes (or an OOB-nonce template) and the
/// oracle used to confirm the vulnerability fired.  All fields are
/// `'static` so the corpus can live in read-only memory.
#[derive(Debug, Clone)]
pub struct CuratedPayload {
    /// Bytes injected into the [`crate::dynamic::spec::PayloadSlot`].
    ///
    /// When [`Self::oob_nonce_slot`] is `true` this field is ignored; the
    /// runner materialises the actual bytes from the OOB listener URL at
    /// call time.
    pub bytes: &'static [u8],
    /// Human label for logs and reports.
    pub label: &'static str,
    /// How we decide the sink fired. See [`Oracle`].
    pub oracle: Oracle,
    /// If `true`, this is a benign control payload.
    /// `Confirmed` requires the vuln payload to trigger AND the benign payload
    /// NOT to trigger (differential confirmation, §4.1).
    pub is_benign: bool,
    /// Where this payload came from.
    pub provenance: PayloadProvenance,
    /// `CORPUS_VERSION` when this payload was added.
    pub since_corpus_version: u32,
    /// `CORPUS_VERSION` at which this payload was deprecated, if any.
    pub deprecated_at_corpus_version: Option<u32>,
    /// Source files that exercise this payload in the dynamic harness.
    /// At least one entry required per §16.1.
    pub fixture_paths: &'static [&'static str],
    /// When `true`, the runner generates the actual bytes from the OOB
    /// listener URL + per-finding nonce at execution time (SSRF OOB variant).
    /// The `bytes` field is unused for such payloads.
    pub oob_nonce_slot: bool,
    /// Structured-oracle predicates evaluated against
    /// [`crate::dynamic::probe::SinkProbe`] records drained from the run's
    /// probe channel (Phase 06 — Track C.1).  Always populated; empty when
    /// the payload still relies on the legacy
    /// [`Oracle::OutputContains`](crate::dynamic::oracle::Oracle::OutputContains)
    /// path and has not been migrated to
    /// [`Oracle::SinkProbe`](crate::dynamic::oracle::Oracle::SinkProbe) yet.
    pub probe_predicates: &'static [ProbePredicate],
    /// Paired benign-control payload inside the same cap's slice.
    ///
    /// `Some(PayloadRef)` on a vulnerable entry means the differential rule
    /// (Phase 07, §4.1) compares this entry's oracle firing against the
    /// referenced benign.  `None` marks the entry as having no paired
    /// control — the runner downgrades any would-be `Confirmed` to
    /// [`crate::evidence::InconclusiveReason::NoBenignControl`].
    /// Always `None` on benign entries themselves.
    pub benign_control: Option<PayloadRef>,
    /// Written rationale required when a non-benign payload has
    /// `benign_control = None`.  Compile-time audit
    /// ([`audit::audit_benign_controls_runtime`]) rejects any entry that
    /// elides the paired control without a non-empty explanation here.
    /// Always `None` on entries that DO carry a `benign_control` and on
    /// benign entries themselves.
    pub no_benign_control_rationale: Option<&'static str>,
}

/// Backward-compatible type alias.
pub type Payload = CuratedPayload;

/// Read-only registry of `(Cap, Lang)` payload slices.
///
/// Constructed once as the [`registry::CORPUS`] const.  Layered as
/// `&'static` slices so the entire registry can live in read-only memory
/// and so [`audit`] can walk it in const eval.
#[derive(Debug, Clone, Copy)]
pub struct CapCorpus {
    /// `(Cap, Lang, payloads)` triples.  A single cap may appear once per
    /// supported language.  See [`registry::payloads_for_lang`] for the
    /// per-language lookup and [`registry::payloads_for`] for the
    /// back-compatible union shim.
    pub entries: &'static [(Cap, Lang, &'static [CuratedPayload])],
    /// Per-cap probe predicates lifted off individual payloads.  Reserved
    /// for later Track J phases; empty in Phase 02.
    pub oracles: &'static [(Cap, &'static [ProbePredicate])],
}
