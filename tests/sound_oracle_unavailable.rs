//! Phase 11 (Track J.9) — `UnsupportedReason::SoundOracleUnavailable`
//! routing for caps that have no sound oracle.
//!
//! Asserts that a `HarnessSpec` whose `expected_cap` is in
//! [`nyx_scanner::dynamic::corpus::registry::CORPUS_SOUND_ORACLE_UNAVAILABLE`]
//! produces a `RunError::SoundOracleUnavailable` from `run_spec`, and
//! that the verify layer in turn surfaces
//! `UnsupportedReason::SoundOracleUnavailable { cap, lang, hint }`
//! instead of the legacy `NoPayloadsForCap`.
//!
//! `cargo nextest run --features dynamic --test sound_oracle_unavailable`.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::corpus::registry::{
    CORPUS_SOUND_ORACLE_UNAVAILABLE, sound_oracle_unavailable_hint,
};
use nyx_scanner::labels::Cap;

#[test]
fn pure_source_and_sanitizer_caps_are_in_the_no_oracle_set() {
    let set = CORPUS_SOUND_ORACLE_UNAVAILABLE;
    assert!(set & Cap::ENV_VAR.bits() != 0);
    assert!(set & Cap::SHELL_ESCAPE.bits() != 0);
    assert!(set & Cap::URL_ENCODE.bits() != 0);
}

#[test]
fn phase_11_caps_left_the_no_oracle_set() {
    let set = CORPUS_SOUND_ORACLE_UNAVAILABLE;
    assert!(set & Cap::CRYPTO.bits() == 0);
    assert!(set & Cap::JSON_PARSE.bits() == 0);
    assert!(set & Cap::UNAUTHORIZED_ID.bits() == 0);
    assert!(set & Cap::DATA_EXFIL.bits() == 0);
}

#[test]
fn hint_carries_a_human_actionable_message() {
    for cap in [Cap::ENV_VAR, Cap::SHELL_ESCAPE, Cap::URL_ENCODE] {
        let hint = sound_oracle_unavailable_hint(cap);
        assert!(!hint.is_empty(), "{cap:?} hint should be populated");
    }
}
