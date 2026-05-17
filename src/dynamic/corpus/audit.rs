//! Compile-time + runtime audits over the corpus registry.
//!
//! Two invariants enforced here fail the build (via `const _: () = assert!(...)`)
//! if they regress:
//!
//! 1. **`benign_control` resolves locally.**  Every non-benign payload either
//!    references a benign control whose `label` appears inside the same
//!    `(cap, lang)` slice, *or* carries an explicit
//!    [`CuratedPayload::no_benign_control_rationale`] with a non-empty
//!    written rationale.  Without this guard the differential rule
//!    (§4.1) silently downgrades to `Inconclusive(NoBenignControl)`
//!    whenever a maintainer forgets to wire a paired benign entry.
//!
//! 2. **Cap coverage is exhaustive.**  The set of caps appearing in
//!    [`CORPUS::entries`] OR [`CORPUS_UNSUPPORTED_LANG_NEUTRAL`] must
//!    equal [`Cap::all`].  Adding a new `Cap` bit without classifying it
//!    fails the build.
//!
//! The runtime `corpus_registry::audit` test mirrors both checks so
//! failure surfaces in `cargo test` output, not just `cargo build`.

use super::registry::{CORPUS, CORPUS_UNSUPPORTED_LANG_NEUTRAL};
use super::CuratedPayload;
use crate::labels::Cap;

/// Byte-level equality for `&'static str` usable in const eval.
const fn str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut i = 0;
    while i < ab.len() {
        if ab[i] != bb[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Walk every `(cap, lang)` slice; for each non-benign payload check that
/// either its `benign_control.label` resolves inside the same slice or it
/// carries a non-empty `no_benign_control_rationale`.
const fn audit_benign_controls() -> bool {
    let entries = CORPUS.entries;
    let mut e = 0;
    while e < entries.len() {
        let slice: &[CuratedPayload] = entries[e].2;
        let mut i = 0;
        while i < slice.len() {
            let p = &slice[i];
            if !p.is_benign {
                match p.benign_control {
                    Some(r) => {
                        let mut j = 0;
                        let mut found = false;
                        while j < slice.len() {
                            if slice[j].is_benign && str_eq(slice[j].label, r.label) {
                                found = true;
                                break;
                            }
                            j += 1;
                        }
                        if !found {
                            return false;
                        }
                    }
                    None => match p.no_benign_control_rationale {
                        Some(rationale) => {
                            if rationale.is_empty() {
                                return false;
                            }
                        }
                        None => return false,
                    },
                }
            }
            i += 1;
        }
        e += 1;
    }
    true
}

/// OR of cap bits appearing in `CORPUS.entries`.
const fn registered_cap_bits() -> u32 {
    let entries = CORPUS.entries;
    let mut bits = 0u32;
    let mut i = 0;
    while i < entries.len() {
        bits |= entries[i].0.bits();
        i += 1;
    }
    bits
}

/// Compile-time guards.  Bumping or breaking these fails `cargo build`.
const _: () = assert!(
    audit_benign_controls(),
    "corpus audit: a non-benign payload references a `benign_control` whose \
     label does not resolve inside its own (cap, lang) slice AND carries no \
     `no_benign_control_rationale` — see src/dynamic/corpus/audit.rs.",
);

const _: () = assert!(
    registered_cap_bits() | CORPUS_UNSUPPORTED_LANG_NEUTRAL == Cap::all().bits(),
    "corpus audit: union of (cap, lang) entries and \
     `CORPUS_UNSUPPORTED_LANG_NEUTRAL` does not cover every `Cap` bit. \
     Add the missing cap to either a `(cap, lang)` slice or the \
     lang-neutral unsupported list.",
);

/// Runtime mirror of the compile-time benign-control audit.
pub fn audit_benign_controls_runtime() -> Result<(), String> {
    for &(cap, lang, slice) in CORPUS.entries {
        for p in slice {
            if p.is_benign {
                continue;
            }
            match p.benign_control {
                Some(r) => {
                    let found = slice
                        .iter()
                        .any(|q| q.is_benign && q.label == r.label);
                    if !found {
                        return Err(format!(
                            "({:?}, {:?}) vuln payload {:?} references missing \
                             benign_control label {:?}",
                            cap, lang, p.label, r.label,
                        ));
                    }
                }
                None => match p.no_benign_control_rationale {
                    Some(rationale) if !rationale.is_empty() => {}
                    _ => {
                        return Err(format!(
                            "({:?}, {:?}) vuln payload {:?} has neither a \
                             benign_control nor a written \
                             no_benign_control_rationale",
                            cap, lang, p.label,
                        ));
                    }
                },
            }
        }
    }
    Ok(())
}

/// Runtime mirror of the compile-time cap-coverage audit.
pub fn audit_cap_coverage_runtime() -> Result<(), String> {
    let covered = registered_cap_bits() | CORPUS_UNSUPPORTED_LANG_NEUTRAL;
    if covered != Cap::all().bits() {
        let missing = Cap::all().bits() & !covered;
        return Err(format!(
            "Cap bits {missing:#x} are neither registered in CORPUS.entries \
             nor listed in CORPUS_UNSUPPORTED_LANG_NEUTRAL",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod corpus_registry {
    use super::*;

    /// Plan §02 acceptance: `cargo test corpus_registry::audit` must pass.
    /// The test name and module name jointly form the required path.
    #[test]
    fn audit() {
        audit_benign_controls_runtime().expect("benign_control audit failed");
        audit_cap_coverage_runtime().expect("cap coverage audit failed");
    }
}
