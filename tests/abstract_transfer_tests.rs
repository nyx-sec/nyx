//! Per-parameter [`AbstractTransfer`] channel unit tests.
//!
//! Covers three correctness surfaces:
//!   * Serde round-trip for every transfer form (so DB-persisted summaries
//!     are stable across restart).
//!   * Direct `apply` behaviour on [`IntervalFact`] / [`StringFact`] inputs
//!     (so the caller-side synthesis of a return abstract value is
//!     predictable).
//!   * Join semantics when multiple return paths or multiple parameters
//!     contribute competing transforms.
//!
//! The pass-1 extraction and pass-2 call-site application integration are
//! covered by the fixture-driven integration tests in
//! `tests/fixtures/cross_file_abstract/` exercised through the main scan
//! harness; unit tests here exercise the primitives in isolation.

use nyx_scanner::abstract_interp::{
    AbstractTransfer, AbstractValue, BitFact, IntervalFact, IntervalTransfer,
    MAX_LITERAL_PREFIX_LEN, PathFact, StringFact, StringTransfer,
};

// ── Serde round-trip ───────────────────────────────────────────────────

#[test]
fn serde_round_trip_default_top() {
    let t = AbstractTransfer::default();
    assert!(t.is_top());
    let json = serde_json::to_string(&t).unwrap();
    // Top is the default; serialisation skips both subdomain fields.
    assert_eq!(json, "{}");
    let back: AbstractTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
    assert!(back.is_top());
}

#[test]
fn serde_round_trip_interval_identity() {
    let t = AbstractTransfer {
        interval: IntervalTransfer::Identity,
        string: StringTransfer::Unknown,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: AbstractTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn serde_round_trip_interval_affine() {
    let t = AbstractTransfer {
        interval: IntervalTransfer::Affine { add: -7, mul: 3 },
        string: StringTransfer::Unknown,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: AbstractTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn serde_round_trip_interval_clamped() {
    let t = AbstractTransfer {
        interval: IntervalTransfer::Clamped {
            lo: 1024,
            hi: 65535,
        },
        string: StringTransfer::Unknown,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: AbstractTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn serde_round_trip_string_identity() {
    let t = AbstractTransfer {
        interval: IntervalTransfer::Top,
        string: StringTransfer::Identity,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: AbstractTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn serde_round_trip_string_literal_prefix() {
    let t = AbstractTransfer {
        interval: IntervalTransfer::Top,
        string: StringTransfer::LiteralPrefix("https://internal.example.com/".into()),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: AbstractTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn serde_round_trip_combined() {
    let t = AbstractTransfer {
        interval: IntervalTransfer::Clamped { lo: 0, hi: 10 },
        string: StringTransfer::LiteralPrefix("safe-".into()),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: AbstractTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn deserialize_legacy_json_missing_fields() {
    // An older SSA summary may carry no `abstract_transfer` entries;
    // the parent's serde(default) handles that.  The transfer record
    // itself must also tolerate both fields missing (reducing to
    // Top/Unknown).
    let back: AbstractTransfer = serde_json::from_str("{}").unwrap();
    assert!(back.is_top());
}

// ── Interval transfer apply ────────────────────────────────────────────

#[test]
fn interval_identity_forwards_input() {
    let t = IntervalTransfer::Identity;
    let input = IntervalFact {
        lo: Some(42),
        hi: Some(100),
    };
    let out = t.apply(&input);
    assert_eq!(out.lo, Some(42));
    assert_eq!(out.hi, Some(100));
}

#[test]
fn interval_top_produces_top() {
    let t = IntervalTransfer::Top;
    let input = IntervalFact::exact(5);
    assert!(t.apply(&input).is_top());
}

#[test]
fn interval_affine_applies() {
    // out = in * 2 + 3; input = [1, 5] → output = [5, 13]
    let t = IntervalTransfer::Affine { add: 3, mul: 2 };
    let input = IntervalFact {
        lo: Some(1),
        hi: Some(5),
    };
    let out = t.apply(&input);
    assert_eq!(out.lo, Some(5));
    assert_eq!(out.hi, Some(13));
}

#[test]
fn interval_clamped_ignores_input() {
    let t = IntervalTransfer::Clamped {
        lo: 1024,
        hi: 65535,
    };
    // Caller argument is unknown; transfer still produces the bound.
    let out = t.apply(&IntervalFact::top());
    assert_eq!(out.lo, Some(1024));
    assert_eq!(out.hi, Some(65535));
    assert!(out.is_proven_bounded());
}

#[test]
fn interval_clamped_reverse_bounds_fall_back_to_top() {
    // Malformed Clamped with lo > hi must not produce a bottom/empty
    // interval (which would be incorrectly-refuted).  Degrade to Top
    // instead so caller-side meet stays sound.
    let t = IntervalTransfer::Clamped { lo: 10, hi: 5 };
    assert!(t.apply(&IntervalFact::top()).is_top());
}

// ── Interval transfer join ─────────────────────────────────────────────

#[test]
fn interval_join_same_identity() {
    let a = IntervalTransfer::Identity;
    let b = IntervalTransfer::Identity;
    assert_eq!(a.join(&b), IntervalTransfer::Identity);
}

#[test]
fn interval_join_clamped_widens_range() {
    let a = IntervalTransfer::Clamped { lo: 0, hi: 10 };
    let b = IntervalTransfer::Clamped { lo: 5, hi: 20 };
    assert_eq!(a.join(&b), IntervalTransfer::Clamped { lo: 0, hi: 20 });
}

#[test]
fn interval_join_identity_vs_clamped_is_top() {
    // Different flow shapes cannot be combined into a single bounded
    // form, conservative fallback is Top.
    let a = IntervalTransfer::Identity;
    let b = IntervalTransfer::Clamped { lo: 0, hi: 10 };
    assert_eq!(a.join(&b), IntervalTransfer::Top);
}

#[test]
fn interval_join_top_absorbs() {
    let a = IntervalTransfer::Top;
    let b = IntervalTransfer::Clamped { lo: 0, hi: 10 };
    assert_eq!(a.join(&b), IntervalTransfer::Top);
    assert_eq!(b.join(&a), IntervalTransfer::Top);
}

// ── String transfer apply ──────────────────────────────────────────────

#[test]
fn string_identity_forwards_input() {
    let t = StringTransfer::Identity;
    let input = StringFact::from_prefix("http://x.com/");
    let out = t.apply(&input);
    assert_eq!(out.prefix.as_deref(), Some("http://x.com/"));
}

#[test]
fn string_unknown_produces_top() {
    let t = StringTransfer::Unknown;
    assert!(t.apply(&StringFact::exact("a")).is_top());
}

#[test]
fn string_literal_prefix_ignores_input() {
    let t = StringTransfer::LiteralPrefix("https://safe.example.com/".into());
    let out = t.apply(&StringFact::top());
    assert_eq!(out.prefix.as_deref(), Some("https://safe.example.com/"));
}

#[test]
fn string_literal_prefix_truncates_oversized() {
    let long = "a".repeat(MAX_LITERAL_PREFIX_LEN + 50);
    let t = StringTransfer::literal_prefix(&long);
    match &t {
        StringTransfer::LiteralPrefix(p) => {
            assert!(
                p.len() <= MAX_LITERAL_PREFIX_LEN,
                "constructor must enforce the size cap"
            );
        }
        _ => panic!("expected LiteralPrefix, got {:?}", t),
    }
}

#[test]
fn string_literal_prefix_empty_degrades_to_unknown() {
    assert_eq!(StringTransfer::literal_prefix(""), StringTransfer::Unknown);
}

// ── String transfer join ───────────────────────────────────────────────

#[test]
fn string_join_same_literal_prefix() {
    let a = StringTransfer::LiteralPrefix("https://safe.com/".into());
    let b = StringTransfer::LiteralPrefix("https://safe.com/".into());
    assert_eq!(a.join(&b), a);
}

#[test]
fn string_join_shared_prefix_keeps_lcp() {
    let a = StringTransfer::LiteralPrefix("https://safe.com/a".into());
    let b = StringTransfer::LiteralPrefix("https://safe.com/b".into());
    match a.join(&b) {
        StringTransfer::LiteralPrefix(p) => assert_eq!(p, "https://safe.com/"),
        other => panic!("expected LCP; got {:?}", other),
    }
}

#[test]
fn string_join_disjoint_prefix_is_unknown() {
    let a = StringTransfer::LiteralPrefix("https://".into());
    let b = StringTransfer::LiteralPrefix("file://".into());
    // LCP is empty → widen to Unknown.
    assert_eq!(a.join(&b), StringTransfer::Unknown);
}

#[test]
fn string_join_identity_vs_prefix_is_unknown() {
    let a = StringTransfer::Identity;
    let b = StringTransfer::LiteralPrefix("x".into());
    assert_eq!(a.join(&b), StringTransfer::Unknown);
}

// ── AbstractTransfer.apply composition ─────────────────────────────────

#[test]
fn transfer_apply_combines_subdomains() {
    let t = AbstractTransfer {
        interval: IntervalTransfer::Identity,
        string: StringTransfer::LiteralPrefix("https://safe.com/".into()),
    };
    let input = AbstractValue {
        interval: IntervalFact::exact(8080),
        string: StringFact::from_prefix("http://untrusted/"),
        bits: BitFact::top(),
        path: PathFact::top(),
    };
    let out = t.apply(&input);
    // Interval identity forwards the caller-known bound.
    assert_eq!(out.interval.lo, Some(8080));
    assert_eq!(out.interval.hi, Some(8080));
    // String literal-prefix overrides the caller-side input, the
    // callee's structural fact wins.
    assert_eq!(out.string.prefix.as_deref(), Some("https://safe.com/"));
    // Bit subdomain is always Top on cross-file transfer by design.
    assert!(out.bits.is_top());
}

#[test]
fn transfer_join_combines_subdomains() {
    let a = AbstractTransfer {
        interval: IntervalTransfer::Clamped { lo: 0, hi: 100 },
        string: StringTransfer::LiteralPrefix("abc".into()),
    };
    let b = AbstractTransfer {
        interval: IntervalTransfer::Clamped { lo: 50, hi: 200 },
        string: StringTransfer::LiteralPrefix("abd".into()),
    };
    let j = a.join(&b);
    assert_eq!(j.interval, IntervalTransfer::Clamped { lo: 0, hi: 200 });
    assert_eq!(j.string, StringTransfer::LiteralPrefix("ab".into()));
}

// ── Pass-1 structural identity detection via scan harness ──────────────
//
// Drives a minimal two-file Python fixture through the fused pass-1
// extraction and checks that the identity-passthrough callee's summary
// carries an `AbstractTransfer::Identity` entry for its sole parameter.
// End-to-end rather than unit-level because the extraction depends on
// the real tree-sitter + SSA lowering pipeline.

use nyx_scanner::ast::analyse_file_fused;
use nyx_scanner::summary::GlobalSummaries;
use nyx_scanner::symbol::Lang;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::Path;

fn test_config() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.scanner.enable_state_analysis = true;
    cfg.scanner.enable_auth_analysis = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 64;
    cfg.performance.channel_multiplier = 1;
    cfg
}

fn pass1(root: &Path, paths: &[std::path::PathBuf], cfg: &Config) -> GlobalSummaries {
    let root_str = root.to_string_lossy();
    let mut gs = GlobalSummaries::new();
    for path in paths {
        let bytes = std::fs::read(path).expect("fixture read");
        let r = analyse_file_fused(&bytes, path, cfg, None, Some(root))
            .expect("analyse_file_fused should succeed on a well-formed fixture");
        for s in r.summaries {
            let key = s.func_key(Some(&root_str));
            gs.insert(key, s);
        }
        for (key, ssa) in r.ssa_summaries {
            gs.insert_ssa(key, ssa);
        }
        for (key, body) in r.ssa_bodies {
            gs.insert_body(key, body);
        }
    }
    gs
}

#[test]
fn passthrough_callee_gets_identity_transfer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Trivial passthrough: `fn passthrough(x): return x`.
    let a_py = root.join("a.py");
    std::fs::write(&a_py, "def passthrough(x):\n    return x\n").expect("write a.py");

    let cfg = test_config();
    let gs = pass1(root, std::slice::from_ref(&a_py), &cfg);

    let ssa = gs.snapshot_ssa();
    let (_, summary) = ssa
        .iter()
        .find(|(k, _)| k.lang == Lang::Python && k.name == "passthrough")
        .expect("SSA summary for passthrough");

    // Exactly one entry; parameter 0 with Identity interval + string.
    assert_eq!(
        summary.abstract_transfer.len(),
        1,
        "passthrough has one param; got {:?}",
        summary.abstract_transfer
    );
    let (idx, t) = &summary.abstract_transfer[0];
    assert_eq!(*idx, 0);
    assert_eq!(
        t.interval,
        IntervalTransfer::Identity,
        "passthrough must produce Identity interval; got {:?}",
        t
    );
    assert_eq!(
        t.string,
        StringTransfer::Identity,
        "passthrough must produce Identity string; got {:?}",
        t
    );
}
