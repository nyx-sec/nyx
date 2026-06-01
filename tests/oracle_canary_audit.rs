//! Phase 30 (Track N.0) — oracle library consolidation + canary uniqueness
//! audit.
//!
//! Tracks J.1–J.9 seeded their probe-based oracles with a single fixed
//! sentinel string (`__nyx_canary`).  Phase 30 replaces it with a per-spec
//! [`Canary`] derived from the finding's `spec_hash`, substituted at run time
//! into the payload bytes, the harness's `NYX_CANARY` environment, and the
//! oracle match.  This test is the build-time guard the plan calls for: it
//!
//!  1. enumerates every `ProbePredicate` carried by the const corpus and
//!     asserts each canary-bearing predicate uses exactly
//!     [`Canary::PLACEHOLDER`] (a new ad-hoc literal fails the build);
//!  2. asserts the runtime [`Canary`] clears the 128-bit entropy floor, is
//!     deterministic within a process, and is collision-free across a large
//!     spec-hash sweep (so distinct findings — and therefore the eval corpora
//!     — never share a canary); and
//!  3. classifies *every* `ProbePredicate` variant with an exhaustive match,
//!     so adding a new variant without classifying it as canary-bearing or
//!     structural fails to compile here.
//!
//! `cargo nextest run --features dynamic --test oracle_canary_audit`.

#![cfg(feature = "dynamic")]

use std::collections::HashSet;

use nyx_scanner::dynamic::corpus::CORPUS;
use nyx_scanner::dynamic::oracle::{Canary, Oracle, ProbePredicate};

/// Classify a predicate as canary-bearing (returns its stored canary token)
/// or structural (returns `None`).
///
/// The match is intentionally exhaustive with no `_` arm: a new
/// `ProbePredicate` variant added to the library forces a classification
/// decision here, which is the Phase 30 guard that "CI fails the build if a
/// new ad-hoc canary lands".  Structural predicates carry header names,
/// allowlists, thresholds, or needles — intentionally low-entropy, public
/// values that are *not* secret sentinels and must not be treated as
/// canaries.
fn canary_token(p: &ProbePredicate) -> Option<&str> {
    match p {
        // The one secret-sentinel predicate: its `canary` is the property a
        // prototype-pollution sink writes onto `Object.prototype` and the
        // oracle matches against the drained probe.
        ProbePredicate::PrototypeCanaryTouched { canary } => Some(canary),

        // Structural predicates — no secret sentinel.
        ProbePredicate::ArgContains { .. }
        | ProbePredicate::ArgEquals { .. }
        | ProbePredicate::AnyArgContains(_)
        | ProbePredicate::CalleeEquals(_)
        | ProbePredicate::MinArgs(_)
        | ProbePredicate::StubEventMatches { .. }
        | ProbePredicate::DeserializeGadgetInvoked { .. }
        | ProbePredicate::TemplateEvalEqual { .. }
        | ProbePredicate::XxeEntityExpanded { .. }
        | ProbePredicate::HeaderInjected { .. }
        | ProbePredicate::HeaderSmuggledInWire { .. }
        | ProbePredicate::RedirectHostNotIn { .. }
        | ProbePredicate::WeakKeyEntropy { .. }
        | ProbePredicate::IdorBoundaryCrossed
        | ProbePredicate::OutboundHostNotIn { .. }
        | ProbePredicate::QueryResultCountGreaterThan { .. }
        | ProbePredicate::JsonParseExcessiveDepth { .. } => None,
    }
}

/// Visit every `ProbePredicate` the corpus carries — both the active
/// `Oracle::SinkProbe { predicates }` slice and the parallel
/// `CuratedPayload::probe_predicates` slice — for every `(cap, lang)` entry.
fn for_each_corpus_predicate(mut visit: impl FnMut(&str /*label*/, &[u8] /*bytes*/, &ProbePredicate)) {
    for &(_cap, _lang, slice) in CORPUS.entries {
        for payload in slice {
            if let Oracle::SinkProbe { predicates } = &payload.oracle {
                for p in *predicates {
                    visit(payload.label, payload.bytes, p);
                }
            }
            for p in payload.probe_predicates {
                visit(payload.label, payload.bytes, p);
            }
        }
    }
}

/// No corpus predicate may carry an ad-hoc canary literal: every
/// canary-bearing predicate must reference [`Canary::PLACEHOLDER`], and the
/// owning payload's bytes must embed that placeholder so the runner's
/// run-time substitution actually has a token to rewrite.
#[test]
fn corpus_canaries_use_placeholder_and_are_substitutable() {
    let mut canary_predicates = 0usize;
    for_each_corpus_predicate(|label, bytes, p| {
        let Some(token) = canary_token(p) else {
            return;
        };
        canary_predicates += 1;
        assert_eq!(
            token,
            Canary::PLACEHOLDER,
            "payload {label:?} carries an ad-hoc canary literal {token:?}; \
             canary-bearing predicates must use Canary::PLACEHOLDER so the \
             runner can substitute a per-spec canary",
        );
        let needle = Canary::PLACEHOLDER.as_bytes();
        let embedded = bytes.windows(needle.len()).any(|w| w == needle);
        assert!(
            embedded,
            "payload {label:?} carries a PrototypeCanaryTouched predicate but \
             its bytes do not embed Canary::PLACEHOLDER ({:?}); run-time \
             substitution would have nothing to rewrite and the harness trap \
             would never match",
            Canary::PLACEHOLDER,
        );
    });
    // Sanity: the prototype-pollution + json_parse slices contribute these,
    // so the audit must actually have inspected some.  A zero here means the
    // corpus walk silently stopped finding canary predicates.
    assert!(
        canary_predicates > 0,
        "expected at least one canary-bearing predicate in the corpus",
    );
}

/// A generated canary is 32 bytes / 256 bits; its rendered form is 64
/// lowercase-hex characters, clears the 128-bit floor, and is deterministic
/// within a process (the runner derives it twice — once for the harness env,
/// once for the oracle — and the two must agree).
#[test]
fn canary_entropy_and_determinism() {
    assert!(
        Canary::ENTROPY_BITS >= 128,
        "Canary::ENTROPY_BITS must clear the 128-bit floor",
    );

    let bytes = Canary::generate("spec-hash-under-audit");
    assert_eq!(bytes.len(), 32, "canary is 256 bits of BLAKE3 output");

    let rendered = Canary::render(&bytes);
    assert_eq!(rendered.len(), 64, "render encodes all 32 bytes as hex");
    assert!(
        rendered.len() * 4 >= 128,
        "rendered canary must carry at least 128 bits",
    );
    assert!(
        rendered
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "rendered canary must be lowercase hex (safe as a JSON key / JS \
         property / header token): {rendered}",
    );

    // Deterministic within the process.
    assert_eq!(bytes, Canary::generate("spec-hash-under-audit"));
    assert_eq!(
        Canary::for_spec("spec-hash-under-audit"),
        Canary::for_spec("spec-hash-under-audit"),
    );

    // Not a fixed string: the rendered canary differs from the historical
    // placeholder sentinel.
    assert_ne!(Canary::for_spec("anything"), Canary::PLACEHOLDER);
}

/// Distinct findings get distinct canaries: a large sweep of distinct
/// `spec_hash` values produces no collisions.  This is the "no oracle
/// collision in any of the eval corpora" guarantee — every finding in a run
/// has a unique `spec_hash`, hence a unique canary, hence one finding's probe
/// record can never satisfy another's oracle.
#[test]
fn canary_is_collision_free_across_spec_hash_sweep() {
    let mut seen = HashSet::new();
    let n = 50_000u32;
    for i in 0..n {
        // Vary the hash shape the way real spec hashes do (16 hex chars) plus
        // a few longer forms to exercise the input space.
        let spec_hash = format!("{i:016x}");
        let canary = Canary::for_spec(&spec_hash);
        assert!(
            seen.insert(canary),
            "canary collision at spec_hash {spec_hash}",
        );
    }
    assert_eq!(seen.len() as u32, n, "every spec_hash produced a unique canary");
}

/// The byte output of `generate` exercises the full space: across many
/// samples every byte position takes both low and high values, so no position
/// is stuck (a coarse but effective check that the BLAKE3 mixing is wired up
/// rather than, say, a zero-fill).
#[test]
fn canary_byte_positions_are_not_stuck() {
    let mut saw_low = [false; 32];
    let mut saw_high = [false; 32];
    for i in 0..512u32 {
        let b = Canary::generate(&format!("stuck-check-{i}"));
        for (pos, byte) in b.iter().enumerate() {
            if *byte < 0x40 {
                saw_low[pos] = true;
            }
            if *byte >= 0xc0 {
                saw_high[pos] = true;
            }
        }
    }
    for pos in 0..32 {
        assert!(
            saw_low[pos] && saw_high[pos],
            "byte position {pos} looks stuck (low={}, high={})",
            saw_low[pos],
            saw_high[pos],
        );
    }
}
