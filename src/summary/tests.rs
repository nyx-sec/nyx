use super::*;
use smallvec::smallvec;

/// Test helper: build a [`SmallVec`] of one cap-only [`SinkSite`] for a
/// parameter, matching the pre-`SinkSite` shape `(idx, Cap)`.  Source
/// coordinates stay default (`line=0, col=0`) since tests do not
/// exercise the primary-location attribution path at this layer.
fn cap_sites(cap: Cap) -> SmallVec<[SinkSite; 1]> {
    smallvec![SinkSite::cap_only(cap)]
}

fn make(name: &str, src: u32, san: u32, sink: u32) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: "test.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: src,
        sanitizer_caps: san,
        sink_caps: sink,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    }
}

#[test]
fn merge_unions_conservatively() {
    let a = make("foo", 0x01, 0x00, 0x00);
    let b = FuncSummary {
        sink_caps: 0x04,
        propagating_params: vec![0],
        tainted_sink_params: vec![0],
        callees: vec!["bar".into()],
        ..make("foo", 0x00, 0x02, 0x00)
    };

    let merged = merge_summaries(vec![a, b], None);
    let key = FuncKey::from_parts(
        Lang::Rust,
        "test.rs",
        String::new(),
        "foo",
        Some(0),
        None,
        FuncKind::Function,
    );
    let foo = merged.get(&key).unwrap();

    assert_eq!(foo.source_caps, 0x01);
    assert_eq!(foo.sanitizer_caps, 0x02);
    assert_eq!(foo.sink_caps, 0x04);
    assert!(foo.propagates_any());
    assert_eq!(foo.propagating_params, vec![0]);
    assert_eq!(foo.tainted_sink_params, vec![0]);
    assert_eq!(foo.callees.len(), 1);
    assert_eq!(foo.callees[0].name, "bar");
}

#[test]
fn same_lang_different_namespace_no_merge() {
    let a = FuncSummary {
        name: "helper".into(),
        file_path: "file_a.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: Cap::all().bits(),
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };
    let b = FuncSummary {
        name: "helper".into(),
        file_path: "file_b.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: Cap::SHELL_ESCAPE.bits(),
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };

    let global = merge_summaries(vec![a, b], None);

    // They should be stored under different FuncKeys
    let key_a = FuncKey::from_parts(
        Lang::Rust,
        "file_a.rs",
        String::new(),
        "helper",
        Some(0),
        None,
        FuncKind::Function,
    );
    let key_b = FuncKey::from_parts(
        Lang::Rust,
        "file_b.rs",
        String::new(),
        "helper",
        Some(0),
        None,
        FuncKind::Function,
    );
    assert!(global.get(&key_a).is_some());
    assert!(global.get(&key_b).is_some());
    // source_caps NOT merged
    assert_eq!(global.get(&key_a).unwrap().source_caps, Cap::all().bits());
    assert_eq!(global.get(&key_b).unwrap().source_caps, 0);
}

#[test]
fn same_lang_same_namespace_merges() {
    let a = FuncSummary {
        name: "helper".into(),
        file_path: "lib.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 0x01,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };
    let b = FuncSummary {
        name: "helper".into(),
        file_path: "lib.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 0,
        sanitizer_caps: 0x02,
        sink_caps: 0,
        propagating_params: vec![0],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };

    let global = merge_summaries(vec![a, b], None);
    let key = FuncKey::from_parts(
        Lang::Rust,
        "lib.rs",
        String::new(),
        "helper",
        Some(0),
        None,
        FuncKind::Function,
    );
    let merged = global.get(&key).unwrap();
    assert_eq!(merged.source_caps, 0x01);
    assert_eq!(merged.sanitizer_caps, 0x02);
    assert!(merged.propagates_any());
    assert_eq!(merged.propagating_params, vec![0]);
}

#[test]
fn cross_lang_name_collision_stays_separate() {
    let py = FuncSummary {
        name: "process_data".into(),
        file_path: "handler.py".into(),
        lang: "python".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: Cap::all().bits(),
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };
    let c = FuncSummary {
        name: "process_data".into(),
        file_path: "handler.c".into(),
        lang: "c".into(),
        param_count: 1,
        param_names: vec!["s".into()],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![0],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };

    let global = merge_summaries(vec![py, c], None);

    let py_key = FuncKey::from_parts(
        Lang::Python,
        "handler.py",
        String::new(),
        "process_data",
        Some(0),
        None,
        FuncKind::Function,
    );
    let c_key = FuncKey::from_parts(
        Lang::C,
        "handler.c",
        String::new(),
        "process_data",
        Some(1),
        None,
        FuncKind::Function,
    );

    assert!(global.get(&py_key).is_some());
    assert!(global.get(&c_key).is_some());
    // Python's source_caps NOT merged into C
    assert_eq!(global.get(&c_key).unwrap().source_caps, 0);
    assert_eq!(global.get(&py_key).unwrap().source_caps, Cap::all().bits());
}

#[test]
fn lookup_same_lang_returns_all_matches() {
    let a = FuncSummary {
        name: "helper".into(),
        file_path: "a.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 1,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };
    let b = FuncSummary {
        name: "helper".into(),
        file_path: "b.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 2,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };

    let global = merge_summaries(vec![a, b], None);
    let matches = global.lookup_same_lang(Lang::Rust, "helper");
    assert_eq!(matches.len(), 2);

    // No cross-language matches
    let py_matches = global.lookup_same_lang(Lang::Python, "helper");
    assert!(py_matches.is_empty());
}

#[test]
fn cap_bits_round_trip_serde() {
    let summary = FuncSummary {
        name: "dangerous".into(),
        file_path: "test.rs".into(),
        lang: "rust".into(),
        param_count: 1,
        param_names: vec!["input".into()],
        source_caps: (Cap::SQL_QUERY | Cap::CODE_EXEC).bits(),
        sanitizer_caps: Cap::CRYPTO.bits(),
        sink_caps: (Cap::SSRF | Cap::DESERIALIZE).bits(),
        propagating_params: vec![0],
        propagates_taint: false,
        tainted_sink_params: vec![0],
        callees: vec!["query".into()],
        ..Default::default()
    };

    let json = serde_json::to_string(&summary).unwrap();
    let back: FuncSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(back.source_caps, (Cap::SQL_QUERY | Cap::CODE_EXEC).bits());
    assert_eq!(back.sanitizer_caps, Cap::CRYPTO.bits());
    assert_eq!(back.sink_caps, (Cap::SSRF | Cap::DESERIALIZE).bits());
    assert!(back.propagates_any());
    assert_eq!(back.propagating_params, vec![0]);
    // propagates_taint should NOT appear in serialized output
    assert!(!json.contains("propagates_taint"));
}

/// Every new cap class persists across the serde JSON round-trip used
/// for SQLite blob storage and the `/debug` endpoint.  Catches a
/// width-mismatch (cap bits truncated to u16) as a hard fail rather than
/// silent zeroing of the upper bits.
#[test]
fn new_cap_classes_round_trip_serde() {
    let new_caps = Cap::LDAP_INJECTION
        | Cap::XPATH_INJECTION
        | Cap::HEADER_INJECTION
        | Cap::OPEN_REDIRECT
        | Cap::SSTI
        | Cap::XXE
        | Cap::PROTOTYPE_POLLUTION;

    // Sanity: bit-width must accommodate every new cap.
    assert_ne!(
        new_caps.bits(),
        0,
        "every new cap must carry a non-zero bit"
    );
    assert_eq!(
        new_caps.bits().count_ones(),
        7,
        "exactly seven bits must be set across the new caps"
    );

    // Bit collisions with existing caps would mask a finding.
    let existing = Cap::ENV_VAR
        | Cap::HTML_ESCAPE
        | Cap::SHELL_ESCAPE
        | Cap::URL_ENCODE
        | Cap::JSON_PARSE
        | Cap::FILE_IO
        | Cap::FMT_STRING
        | Cap::SQL_QUERY
        | Cap::DESERIALIZE
        | Cap::SSRF
        | Cap::CODE_EXEC
        | Cap::CRYPTO
        | Cap::UNAUTHORIZED_ID
        | Cap::DATA_EXFIL;
    assert!(
        (existing & new_caps).is_empty(),
        "new caps must not collide"
    );

    let summary = FuncSummary {
        name: "all_new_classes".into(),
        file_path: "fixture.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: new_caps.bits(),
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };

    // serde JSON round-trip (the on-disk SQLite format).
    let json = serde_json::to_string(&summary).unwrap();
    let back: FuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sink_caps, new_caps.bits());
    assert!(back.sink_caps().contains(Cap::LDAP_INJECTION));
    assert!(back.sink_caps().contains(Cap::PROTOTYPE_POLLUTION));

    // Cap registry must surface a rule id for each new cap.
    for cap in [
        Cap::LDAP_INJECTION,
        Cap::XPATH_INJECTION,
        Cap::HEADER_INJECTION,
        Cap::OPEN_REDIRECT,
        Cap::SSTI,
        Cap::XXE,
        Cap::PROTOTYPE_POLLUTION,
    ] {
        let meta = crate::labels::cap_rule_meta(cap)
            .unwrap_or_else(|| panic!("missing CAP_RULE_REGISTRY entry for {cap:?}"));
        assert!(meta.rule_id.starts_with("taint-"));
        assert!(!meta.title.is_empty());
        assert!(!meta.description.is_empty());
    }
}

#[test]
fn backward_compat_u8_json_deserializes() {
    // Old u8-range values still deserialize correctly into u32 fields
    let json = r#"{
        "name": "old_func",
        "file_path": "legacy.py",
        "lang": "python",
        "param_count": 0,
        "param_names": [],
        "source_caps": 127,
        "sanitizer_caps": 2,
        "sink_caps": 4,
        "propagates_taint": false,
        "tainted_sink_params": [],
        "callees": []
    }"#;

    let summary: FuncSummary = serde_json::from_str(json).unwrap();
    assert_eq!(summary.source_caps, 127);
    assert_eq!(summary.sanitizer_caps, 2);
    assert_eq!(summary.sink_caps, 4);
}

#[test]
fn merge_propagating_params_union() {
    let a = FuncSummary {
        propagating_params: vec![0],
        ..make("foo", 0, 0, 0)
    };
    let b = FuncSummary {
        propagating_params: vec![1],
        ..make("foo", 0, 0, 0)
    };

    let merged = merge_summaries(vec![a, b], None);
    let key = FuncKey::from_parts(
        Lang::Rust,
        "test.rs",
        String::new(),
        "foo",
        Some(0),
        None,
        FuncKind::Function,
    );
    let foo = merged.get(&key).unwrap();
    assert_eq!(foo.propagating_params, vec![0, 1]);
    assert!(foo.propagates_any());
}

#[test]
fn backward_compat_legacy_propagates_taint_json() {
    // Old JSON with propagates_taint: true but no propagating_params
    let json = r#"{
        "name": "old_func",
        "file_path": "legacy.py",
        "lang": "python",
        "param_count": 1,
        "param_names": ["x"],
        "source_caps": 0,
        "sanitizer_caps": 0,
        "sink_caps": 0,
        "propagates_taint": true,
        "tainted_sink_params": [],
        "callees": []
    }"#;

    let summary: FuncSummary = serde_json::from_str(json).unwrap();
    assert!(summary.propagates_taint);
    assert!(summary.propagating_params.is_empty());
    assert!(summary.propagates_any());
}

#[test]
fn propagating_params_round_trip_serde() {
    let summary = FuncSummary {
        propagating_params: vec![0, 2],
        ..make("foo", 0, 0, 0)
    };

    let json = serde_json::to_string(&summary).unwrap();
    let back: FuncSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(back.propagating_params, vec![0, 2]);
    assert!(back.propagates_any());
    // propagates_taint must NOT appear in serialized output
    assert!(!json.contains("propagates_taint"));
}

#[test]
fn snapshot_caps_detects_change() {
    let a = FuncSummary {
        source_caps: 0x01,
        propagating_params: vec![0],
        ..make("foo", 0, 0, 0)
    };
    let b = make("bar", 0, 0, 0x04);

    let mut gs = merge_summaries(vec![a, b], None);

    let snap1 = gs.snapshot_caps();

    // Mutate one summary by inserting a changed version.
    let key = FuncKey::from_parts(
        Lang::Rust,
        "test.rs",
        String::new(),
        "bar",
        Some(0),
        None,
        FuncKind::Function,
    );
    let updated = FuncSummary {
        sink_caps: 0x08,
        ..make("bar", 0, 0, 0)
    };
    gs.insert(key, updated);

    let snap2 = gs.snapshot_caps();

    assert_ne!(snap1, snap2, "snapshot should detect changed caps");

    // Without further changes, snapshot should be stable.
    let snap3 = gs.snapshot_caps();
    assert_eq!(snap2, snap3, "snapshot should be stable without changes");
}

// ── SSA summary tests ───────────────────────────────────────────────────

use super::ssa_summary::{SsaFuncSummary, TaintTransform};

#[test]
fn ssa_summary_serde_round_trip_identity() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn ssa_summary_serde_round_trip_strip_bits() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(
            0,
            TaintTransform::StripBits(Cap::HTML_ESCAPE | Cap::URL_ENCODE),
        )],
        param_to_sink: vec![(1, cap_sites(Cap::SQL_QUERY))],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn ssa_summary_serde_round_trip_add_bits() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(2, TaintTransform::AddBits(Cap::CODE_EXEC))],
        param_to_sink: vec![],
        source_caps: Cap::ENV_VAR | Cap::FILE_IO,
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn ssa_summary_serde_round_trip_all_variants() {
    let summary = SsaFuncSummary {
        param_to_return: vec![
            (0, TaintTransform::Identity),
            (1, TaintTransform::StripBits(Cap::SHELL_ESCAPE)),
            (2, TaintTransform::AddBits(Cap::SSRF)),
        ],
        param_to_sink: vec![
            (0, cap_sites(Cap::SQL_QUERY)),
            (1, cap_sites(Cap::CODE_EXEC | Cap::CRYPTO)),
        ],
        source_caps: Cap::all(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn global_summaries_insert_ssa_exact_key_replacement() {
    let mut gs = GlobalSummaries::new();
    let key = FuncKey::from_parts(
        Lang::Python,
        "app.py",
        String::new(),
        "process",
        Some(1),
        None,
        FuncKind::Function,
    );

    let v1 = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    gs.insert_ssa(key.clone(), v1.clone());
    assert_eq!(gs.get_ssa(&key), Some(&v1));

    // Replace with a different summary, exact replacement, not union
    let v2 = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))],
        param_to_sink: vec![(0, cap_sites(Cap::SQL_QUERY))],
        source_caps: Cap::ENV_VAR,
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    gs.insert_ssa(key.clone(), v2.clone());
    assert_eq!(gs.get_ssa(&key), Some(&v2));
}

#[test]
fn global_summaries_merge_with_ssa_entries() {
    let mut gs1 = GlobalSummaries::new();
    let mut gs2 = GlobalSummaries::new();

    let key_a = FuncKey::from_parts(
        Lang::Python,
        "a.py",
        String::new(),
        "foo",
        Some(1),
        None,
        FuncKind::Function,
    );
    let key_b = FuncKey::from_parts(
        Lang::Python,
        "b.py",
        String::new(),
        "bar",
        Some(2),
        None,
        FuncKind::Function,
    );

    let sum_a = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let sum_b = SsaFuncSummary {
        param_to_return: vec![],
        param_to_sink: vec![(0, cap_sites(Cap::CODE_EXEC))],
        source_caps: Cap::ENV_VAR,
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };

    gs1.insert_ssa(key_a.clone(), sum_a.clone());
    gs2.insert_ssa(key_b.clone(), sum_b.clone());

    gs1.merge(gs2);

    assert_eq!(gs1.get_ssa(&key_a), Some(&sum_a));
    assert_eq!(gs1.get_ssa(&key_b), Some(&sum_b));
}

#[test]
fn global_summaries_is_empty_considers_ssa() {
    let mut gs = GlobalSummaries::new();
    assert!(gs.is_empty());

    let key = FuncKey::from_parts(
        Lang::Rust,
        "lib.rs",
        String::new(),
        "f",
        Some(1),
        None,
        FuncKind::Function,
    );
    gs.insert_ssa(
        key,
        SsaFuncSummary {
            param_to_return: vec![(0, TaintTransform::Identity)],
            param_to_sink: vec![],
            source_caps: Cap::empty(),
            param_to_sink_param: vec![],
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
            source_to_callback: vec![],

            receiver_to_return: None,

            receiver_to_sink: Cap::empty(),

            abstract_transfer: vec![],
            param_return_paths: vec![],
            points_to: Default::default(),
            field_points_to: Default::default(),
            return_path_facts: smallvec::SmallVec::new(),
            typed_call_receivers: vec![],
            validated_params_to_return: smallvec::SmallVec::new(),
            confines_path_params: smallvec::SmallVec::new(),
            asserts_path_confined_params: Default::default(),
            result_reject_guard_params: Default::default(),
            sanitizes_open_redirect_return: false,
            confines_path_return: false,
            param_to_gate_filters: vec![],
            entry_kind: None,
        },
    );

    assert!(!gs.is_empty());
}

#[test]
fn ssa_summary_serde_round_trip_param_to_sink_param() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![(0, cap_sites(Cap::SQL_QUERY))],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![(0, 0, Cap::SQL_QUERY), (1, 0, Cap::CODE_EXEC)],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert_eq!(back.param_to_sink_param.len(), 2);
    assert_eq!(back.param_to_sink_param[0], (0, 0, Cap::SQL_QUERY));
    assert_eq!(back.param_to_sink_param[1], (1, 0, Cap::CODE_EXEC));
}

#[test]
fn ssa_summary_backward_compat_missing_param_to_sink_param() {
    // Old JSON without param_to_sink_param should deserialize with empty vec
    let json = r#"{
        "param_to_return": [[0, "Identity"]],
        "param_to_sink": [],
        "source_caps": 0
    }"#;
    let summary: SsaFuncSummary = serde_json::from_str(json).unwrap();
    assert!(summary.param_to_sink_param.is_empty());
}

#[test]
fn ssa_summary_serde_round_trip_container_fields() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![0],
        param_to_container_store: vec![(1, 0)],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert_eq!(back.param_container_to_return, vec![0]);
    assert_eq!(back.param_to_container_store, vec![(1, 0)]);
}

#[test]
fn ssa_summary_backward_compat_missing_container_fields() {
    // Old JSON without container fields should deserialize with empty vecs
    let json = r#"{
        "param_to_return": [[0, "Identity"]],
        "param_to_sink": [],
        "source_caps": 0
    }"#;
    let summary: SsaFuncSummary = serde_json::from_str(json).unwrap();
    assert!(summary.param_container_to_return.is_empty());
    assert!(summary.param_to_container_store.is_empty());
}

#[test]
fn ssa_summary_serde_round_trip_return_abstract() {
    use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, PathFact, StringFact};

    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: Some(AbstractValue {
            interval: IntervalFact {
                lo: Some(-2_147_483_648),
                hi: Some(2_147_483_647),
            },
            string: StringFact::top(),
            bits: BitFact::top(),
            path: PathFact::top(),
        }),
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert!(back.return_abstract.is_some());
    let abs = back.return_abstract.unwrap();
    assert_eq!(abs.interval.lo, Some(-2_147_483_648));
    assert_eq!(abs.interval.hi, Some(2_147_483_647));
    assert!(abs.string.is_top());
}

#[test]
fn ssa_summary_backward_compat_missing_return_abstract() {
    // Old JSON without return_abstract should deserialize with None
    let json = r#"{
        "param_to_return": [],
        "param_to_sink": [],
        "source_caps": 0
    }"#;
    let summary: SsaFuncSummary = serde_json::from_str(json).unwrap();
    assert_eq!(summary.return_abstract, None);
}

// ── CalleeSsaBody serde + GlobalSummaries body resolution ───────────────

/// Helper: build a minimal CalleeSsaBody with a given number of blocks.
#[allow(dead_code)] // used by tests below
pub(super) fn make_callee_body(
    num_blocks: usize,
    param_count: usize,
) -> crate::taint::ssa_transfer::CalleeSsaBody {
    use crate::ssa::ir::*;
    use smallvec::smallvec;

    let mut blocks = Vec::new();
    for i in 0..num_blocks {
        blocks.push(SsaBlock {
            id: BlockId(i as u32),
            phis: vec![],
            body: vec![SsaInst {
                value: SsaValue(i as u32),
                op: SsaOp::Const(Some("0".into())),
                cfg_node: petgraph::graph::NodeIndex::new(0),
                var_name: None,
                span: (0, 0),
            }],
            terminator: if i + 1 < num_blocks {
                Terminator::Goto(BlockId((i + 1) as u32))
            } else {
                Terminator::Return(Some(SsaValue(0)))
            },
            preds: smallvec![],
            succs: smallvec![],
        });
    }

    let value_defs: Vec<ValueDef> = (0..num_blocks)
        .map(|i| ValueDef {
            var_name: None,
            cfg_node: petgraph::graph::NodeIndex::new(0),
            block: BlockId(i as u32),
        })
        .collect();

    crate::taint::ssa_transfer::CalleeSsaBody {
        ssa: SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs,
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        },
        opt: crate::ssa::OptimizeResult {
            const_values: crate::ssa::const_prop::ConstValues::default(),
            type_facts: crate::ssa::type_facts::TypeFactResult {
                facts: std::collections::HashMap::new(),
            },
            xml_parser_config: crate::ssa::xml_config::XmlParserConfigResult::default(),
            xpath_config: crate::ssa::xpath_config::XPathConfigResult::default(),
            alias_result: crate::ssa::alias::BaseAliasResult::empty(),
            points_to: crate::ssa::heap::PointsToResult::empty(),
            module_aliases: std::collections::HashMap::new(),
            branches_pruned: 0,
            copies_eliminated: 0,
            dead_defs_removed: 0,
        },
        param_count,
        node_meta: std::collections::HashMap::new(),
        body_graph: None,
        cross_package_imports: std::sync::Arc::new(std::collections::HashMap::new()),
    }
}

#[test]
fn callee_body_serde_round_trip_empty() {
    let body = make_callee_body(1, 0);
    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody = serde_json::from_str(&json).unwrap();
    assert_eq!(back.param_count, 0);
    assert_eq!(back.ssa.blocks.len(), 1);
    assert!(back.node_meta.is_empty());
}

#[test]
fn callee_body_serde_round_trip_multi_block() {
    let body = make_callee_body(5, 2);
    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody = serde_json::from_str(&json).unwrap();
    assert_eq!(back.param_count, 2);
    assert_eq!(back.ssa.blocks.len(), 5);
    // Verify block structure survived round-trip
    assert_eq!(back.ssa.entry, crate::ssa::ir::BlockId(0));
    assert_eq!(back.ssa.value_defs.len(), 5);
}

#[test]
fn callee_body_serde_round_trip_with_node_meta() {
    use crate::cfg::{NodeInfo, TaintMeta};
    use crate::labels::{Cap, DataLabel};
    use crate::taint::ssa_transfer::CrossFileNodeMeta;

    let mut body = make_callee_body(2, 1);
    body.node_meta.insert(
        0,
        CrossFileNodeMeta {
            info: NodeInfo {
                bin_op: Some(crate::cfg::BinOp::Add),
                taint: TaintMeta {
                    labels: smallvec::smallvec![DataLabel::Sink(Cap::HTML_ESCAPE)],
                    ..Default::default()
                },
                ..Default::default()
            },
        },
    );
    body.node_meta.insert(
        1,
        CrossFileNodeMeta {
            info: NodeInfo::default(),
        },
    );

    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody = serde_json::from_str(&json).unwrap();

    assert_eq!(back.node_meta.len(), 2);
    let meta0 = &back.node_meta[&0];
    assert_eq!(meta0.info.bin_op, Some(crate::cfg::BinOp::Add));
    assert_eq!(meta0.info.taint.labels.len(), 1);
    assert!(matches!(meta0.info.taint.labels[0], DataLabel::Sink(cap) if cap == Cap::HTML_ESCAPE));
    assert!(back.node_meta[&1].info.taint.labels.is_empty());
}

#[test]
fn callee_body_serde_node_meta_skipped_when_empty() {
    // Verify #[serde(skip_serializing_if)] works: empty node_meta not in JSON
    let body = make_callee_body(1, 0);
    let json = serde_json::to_string(&body).unwrap();
    assert!(
        !json.contains("node_meta"),
        "empty node_meta should be omitted from JSON"
    );

    // But it should deserialize fine from JSON without node_meta field
    let back: crate::taint::ssa_transfer::CalleeSsaBody = serde_json::from_str(&json).unwrap();
    assert!(back.node_meta.is_empty());
}

#[test]
fn callee_body_serde_with_all_ssa_op_variants() {
    use crate::ssa::ir::*;
    use smallvec::smallvec;

    let mut body = make_callee_body(1, 0);
    // Replace the single block's body with all SsaOp variants
    let node = petgraph::graph::NodeIndex::new(0);
    body.ssa.blocks[0].body = vec![
        SsaInst {
            value: SsaValue(0),
            op: SsaOp::Const(Some("hello".into())),
            cfg_node: node,
            var_name: None,
            span: (0, 5),
        },
        SsaInst {
            value: SsaValue(1),
            op: SsaOp::Const(None),
            cfg_node: node,
            var_name: None,
            span: (0, 0),
        },
        SsaInst {
            value: SsaValue(2),
            op: SsaOp::Source,
            cfg_node: node,
            var_name: Some("src".into()),
            span: (6, 10),
        },
        SsaInst {
            value: SsaValue(3),
            op: SsaOp::Param { index: 0 },
            cfg_node: node,
            var_name: Some("p0".into()),
            span: (0, 0),
        },
        SsaInst {
            value: SsaValue(4),
            op: SsaOp::CatchParam,
            cfg_node: node,
            var_name: None,
            span: (0, 0),
        },
        SsaInst {
            value: SsaValue(5),
            op: SsaOp::Nop,
            cfg_node: node,
            var_name: None,
            span: (0, 0),
        },
        SsaInst {
            value: SsaValue(6),
            op: SsaOp::Assign(smallvec![SsaValue(0), SsaValue(1)]),
            cfg_node: node,
            var_name: None,
            span: (0, 0),
        },
        SsaInst {
            value: SsaValue(7),
            op: SsaOp::Call {
                callee: "foo".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)], smallvec![SsaValue(1)]],
                receiver: Some(SsaValue(2)),
            },
            cfg_node: node,
            var_name: None,
            span: (11, 20),
        },
    ];
    body.ssa.blocks[0].phis = vec![SsaInst {
        value: SsaValue(8),
        op: SsaOp::Phi(smallvec![
            (BlockId(0), SsaValue(0)),
            (BlockId(1), SsaValue(1))
        ]),
        cfg_node: node,
        var_name: None,
        span: (0, 0),
    }];

    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody = serde_json::from_str(&json).unwrap();

    assert_eq!(back.ssa.blocks[0].body.len(), 8);
    assert_eq!(back.ssa.blocks[0].phis.len(), 1);

    // Spot check: Call op preserved
    match &back.ssa.blocks[0].body[7].op {
        SsaOp::Call {
            callee,
            args,
            receiver,
            ..
        } => {
            assert_eq!(callee, "foo");
            assert_eq!(args.len(), 2);
            assert_eq!(*receiver, Some(SsaValue(2)));
        }
        other => panic!("expected Call, got {:?}", other),
    }
    // Spot check: Phi op preserved
    match &back.ssa.blocks[0].phis[0].op {
        SsaOp::Phi(ops) => {
            assert_eq!(ops.len(), 2);
            assert_eq!(ops[0], (BlockId(0), SsaValue(0)));
        }
        other => panic!("expected Phi, got {:?}", other),
    }
}

#[test]
fn callee_body_serde_with_branch_terminator() {
    use crate::constraint::lower::ConditionExpr;
    use crate::ssa::ir::*;

    let mut body = make_callee_body(3, 0);
    // Set a Branch terminator with a condition
    body.ssa.blocks[0].terminator = Terminator::Branch {
        cond: petgraph::graph::NodeIndex::new(0),
        true_blk: BlockId(1),
        false_blk: BlockId(2),
        condition: Some(Box::new(ConditionExpr::BoolTest {
            var: SsaValue(0),
            negated: false,
        })),
    };

    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody = serde_json::from_str(&json).unwrap();

    match &back.ssa.blocks[0].terminator {
        Terminator::Branch {
            true_blk,
            false_blk,
            condition,
            ..
        } => {
            assert_eq!(*true_blk, BlockId(1));
            assert_eq!(*false_blk, BlockId(2));
            assert!(condition.is_some());
            match condition.as_deref() {
                Some(ConditionExpr::BoolTest { var, .. }) => {
                    assert_eq!(*var, SsaValue(0));
                }
                other => panic!("expected BoolTest, got {:?}", other),
            }
        }
        other => panic!("expected Branch, got {:?}", other),
    }
}

// ── GlobalSummaries body resolution ──────────────────────────────────────

#[test]
fn global_summaries_insert_body_exact_key_replacement() {
    let mut gs = GlobalSummaries::new();
    let key = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "helper.py",
        String::new(),
        "transform",
        Some(2),
        None,
        FuncKind::Function,
    );

    let body1 = make_callee_body(3, 2);
    let body2 = make_callee_body(5, 2);

    gs.insert_body(key.clone(), body1);
    assert_eq!(gs.get_body(&key).unwrap().ssa.blocks.len(), 3);

    // Second insert replaces (exact-key, no union)
    gs.insert_body(key.clone(), body2);
    assert_eq!(gs.get_body(&key).unwrap().ssa.blocks.len(), 5);
}

/// A body inserted in its stored form answers fingerprint reads, key
/// reconciliation and leaf lookup like the same body inserted decoded,
/// without being decoded until a reader asks for its contents.
#[test]
fn encoded_body_behaves_like_a_decoded_one() {
    use deps::DepOracle;
    let key = |name: &str, arity| {
        FuncKey::from_parts(
            crate::symbol::Lang::Python,
            "helper.py",
            String::new(),
            name,
            Some(arity),
            None,
            FuncKind::Function,
        )
    };
    // The second `transform` collides with the first at a different
    // parameter count, so reconciliation rekeys it.
    let inserts = [
        (key("transform", 2), make_callee_body(3, 2)),
        (key("transform", 2), make_callee_body(4, 3)),
        (key("other", 1), make_callee_body(2, 1)),
    ];
    let mut eager = GlobalSummaries::new();
    let mut lazy = GlobalSummaries::new();
    for (k, body) in &inserts {
        eager.insert_body(k.clone(), body.clone());
        lazy.insert_encoded_body(k.clone(), EncodedBody::encode(body).unwrap());
    }
    let mut keys: Vec<_> = eager.bodies_by_key.keys().cloned().collect();
    keys.sort_by_key(ToString::to_string);
    let mut lazy_keys: Vec<_> = lazy.bodies_by_key.keys().cloned().collect();
    lazy_keys.sort_by_key(ToString::to_string);
    assert_eq!(keys, lazy_keys);
    assert_eq!(keys.len(), 3);

    for k in &keys {
        for kind in [KeyedRead::Body, KeyedRead::BodyShape] {
            assert_eq!(
                lazy.keyed_fp(kind, k),
                eager.keyed_fp(kind, k),
                "{kind:?} {k}"
            );
        }
    }
    let pick = |gs: &GlobalSummaries| {
        let picked = gs.body_by_leaf(crate::symbol::Lang::Python, "transform", 3);
        picked.map(|(b, k)| (b.ssa.blocks.len(), k))
    };
    assert!(
        lazy.bodies_by_key.values().all(|e| !e.v.is_decoded()),
        "fingerprints and leaf filtering must not decode"
    );
    assert_eq!(pick(&lazy), pick(&eager));
    for k in &keys {
        let (a, b) = (lazy.get_body(k).unwrap(), eager.get_body(k).unwrap());
        assert_eq!(a.param_count, b.param_count);
        assert_eq!(a.ssa.blocks.len(), b.ssa.blocks.len());
        assert_eq!(deps::fp_value(a), deps::fp_value(b));
    }
}

#[test]
fn global_summaries_get_body_not_found() {
    let gs = GlobalSummaries::new();
    let key = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "missing.py",
        String::new(),
        "nope",
        Some(0),
        None,
        FuncKind::Function,
    );
    assert!(gs.get_body(&key).is_none());
}

#[test]
fn global_summaries_merge_includes_bodies() {
    let mut gs1 = GlobalSummaries::new();
    let mut gs2 = GlobalSummaries::new();

    let key1 = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "a.py",
        String::new(),
        "func_a",
        Some(1),
        None,
        FuncKind::Function,
    );
    let key2 = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "b.py",
        String::new(),
        "func_b",
        Some(2),
        None,
        FuncKind::Function,
    );

    // Need to also insert regular summaries so the by_lang_name index is populated
    gs1.insert(key1.clone(), make("func_a", 0, 0, 0));
    gs1.insert_body(key1.clone(), make_callee_body(2, 1));

    gs2.insert(key2.clone(), make("func_b", 0, 0, 0));
    gs2.insert_body(key2.clone(), make_callee_body(4, 2));

    gs1.merge(gs2);

    assert!(gs1.get_body(&key1).is_some());
    assert!(gs1.get_body(&key2).is_some());
    assert_eq!(gs1.get_body(&key1).unwrap().ssa.blocks.len(), 2);
    assert_eq!(gs1.get_body(&key2).unwrap().ssa.blocks.len(), 4);
}

#[test]
fn global_summaries_resolve_callee_body_exact_match() {
    let mut gs = GlobalSummaries::new();

    let key = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "util.py",
        String::new(),
        "helper",
        Some(1),
        None,
        FuncKind::Function,
    );

    gs.insert(key.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key.clone(), make_callee_body(3, 1));

    // Resolve with matching lang/name/arity
    let resolved = gs.resolve_callee_body(crate::symbol::Lang::Python, "helper", Some(1), "app.py");
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().ssa.blocks.len(), 3);
}

#[test]
fn global_summaries_resolve_callee_body_not_found() {
    let gs = GlobalSummaries::new();

    let resolved =
        gs.resolve_callee_body(crate::symbol::Lang::Python, "missing", Some(1), "app.py");
    assert!(resolved.is_none());
}

#[test]
fn global_summaries_resolve_callee_body_ambiguous_returns_none() {
    let mut gs = GlobalSummaries::new();

    // Two functions with same name but different namespaces
    let key1 = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "a.py",
        String::new(),
        "helper",
        Some(1),
        None,
        FuncKind::Function,
    );
    let key2 = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "b.py",
        String::new(),
        "helper",
        Some(1),
        None,
        FuncKind::Function,
    );

    gs.insert(key1.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key1.clone(), make_callee_body(2, 1));
    gs.insert(key2.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key2.clone(), make_callee_body(4, 1));

    // Resolution from a third namespace → ambiguous → None
    let resolved = gs.resolve_callee_body(crate::symbol::Lang::Python, "helper", Some(1), "c.py");
    assert!(
        resolved.is_none(),
        "ambiguous resolution should return None"
    );
}

#[test]
fn global_summaries_resolve_callee_body_namespace_disambiguates() {
    let mut gs = GlobalSummaries::new();

    let key1 = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "a.py",
        String::new(),
        "helper",
        Some(1),
        None,
        FuncKind::Function,
    );
    let key2 = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "b.py",
        String::new(),
        "helper",
        Some(1),
        None,
        FuncKind::Function,
    );

    gs.insert(key1.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key1.clone(), make_callee_body(2, 1));
    gs.insert(key2.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key2.clone(), make_callee_body(4, 1));

    // Resolution from a.py → namespace match → key1 (2 blocks)
    let resolved = gs.resolve_callee_body(crate::symbol::Lang::Python, "helper", Some(1), "a.py");
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().ssa.blocks.len(), 2);
}

#[test]
fn global_summaries_resolve_body_requires_body_present() {
    let mut gs = GlobalSummaries::new();

    // Insert summary but no body
    let key = FuncKey::from_parts(
        crate::symbol::Lang::Python,
        "util.py",
        String::new(),
        "helper",
        Some(1),
        None,
        FuncKind::Function,
    );
    gs.insert(key.clone(), make("helper", 0, 0, 0));
    gs.insert_ssa(
        key.clone(),
        SsaFuncSummary {
            param_to_return: vec![],
            param_to_sink: vec![],
            source_caps: crate::labels::Cap::empty(),
            param_to_sink_param: vec![],
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
            source_to_callback: vec![],

            receiver_to_return: None,

            receiver_to_sink: Cap::empty(),

            abstract_transfer: vec![],
            param_return_paths: vec![],
            points_to: Default::default(),
            field_points_to: Default::default(),
            return_path_facts: smallvec::SmallVec::new(),
            typed_call_receivers: vec![],
            validated_params_to_return: smallvec::SmallVec::new(),
            confines_path_params: smallvec::SmallVec::new(),
            asserts_path_confined_params: Default::default(),
            result_reject_guard_params: Default::default(),
            sanitizes_open_redirect_return: false,
            confines_path_return: false,
            param_to_gate_filters: vec![],
            entry_kind: None,
        },
    );
    // Don't insert body

    // Resolution finds the key but no body
    let resolved = gs.resolve_callee_body(crate::symbol::Lang::Python, "helper", Some(1), "app.py");
    assert!(
        resolved.is_none(),
        "should return None when key resolves but no body stored"
    );
}

// ── Identity-model regression tests ─────────────────────────────────────
// Each test below encodes one ambiguity the old `(file, name, arity)` key
// couldn't express.  They guard the new `(lang, namespace, container, name,
// arity, disambig, kind)` model and the container-aware resolver.

fn fs_with(
    namespace: &str,
    container: &str,
    name: &str,
    arity: usize,
    kind: FuncKind,
    disambig: Option<u32>,
    sink_bits: u32,
) -> (FuncKey, FuncSummary) {
    let key = FuncKey::from_parts(
        Lang::Java,
        namespace,
        container,
        name,
        Some(arity),
        disambig,
        kind,
    );
    let summary = FuncSummary {
        name: name.into(),
        file_path: namespace.into(),
        lang: "java".into(),
        param_count: arity,
        sink_caps: sink_bits,
        container: container.into(),
        disambig,
        kind,
        ..Default::default()
    };
    (key, summary)
}

#[test]
fn same_name_methods_on_different_classes_stay_distinct() {
    let mut gs = GlobalSummaries::new();
    let (k1, s1) = fs_with(
        "src/svc.java",
        "OrderService",
        "process",
        1,
        FuncKind::Method,
        Some(100),
        0x01,
    );
    let (k2, s2) = fs_with(
        "src/svc.java",
        "UserService",
        "process",
        1,
        FuncKind::Method,
        Some(500),
        0x02,
    );
    gs.insert(k1.clone(), s1);
    gs.insert(k2.clone(), s2);

    assert_eq!(gs.get(&k1).unwrap().sink_caps, 0x01);
    assert_eq!(gs.get(&k2).unwrap().sink_caps, 0x02);

    let order = gs.resolve_callee_key_with_container(
        "process",
        Lang::Java,
        "src/other.java",
        Some("OrderService"),
        Some(1),
    );
    assert_eq!(order, CalleeResolution::Resolved(k1));

    let user = gs.resolve_callee_key_with_container(
        "process",
        Lang::Java,
        "src/other.java",
        Some("UserService"),
        Some(1),
    );
    assert_eq!(user, CalleeResolution::Resolved(k2));
}

#[test]
fn free_function_and_method_with_same_name_resolve_separately() {
    let mut gs = GlobalSummaries::new();
    let (kf, sf) = fs_with(
        "src/app.java",
        "",
        "process",
        1,
        FuncKind::Function,
        Some(10),
        0x10,
    );
    let (km, sm) = fs_with(
        "src/app.java",
        "Worker",
        "process",
        1,
        FuncKind::Method,
        Some(200),
        0x20,
    );
    gs.insert(kf.clone(), sf);
    gs.insert(km.clone(), sm);

    let free =
        gs.resolve_callee_key_with_container("process", Lang::Java, "src/app.java", None, Some(1));
    let method = gs.resolve_callee_key_with_container(
        "process",
        Lang::Java,
        "src/app.java",
        Some("Worker"),
        Some(1),
    );
    assert_eq!(method, CalleeResolution::Resolved(km));

    // Without any qualifier, receiver, or receiver_type, a bare
    // `process()` call is syntactically a free-function invocation, a
    // method cannot be invoked that way from outside its class.  The
    // resolver's bare-call preference (step 5.5) picks the sole
    // empty-container candidate deterministically.
    assert_eq!(free, CalleeResolution::Resolved(kf));
}

#[test]
fn disambig_separates_same_name_closures_in_same_container() {
    let mut gs = GlobalSummaries::new();
    let (k1, s1) = fs_with(
        "src/f.js",
        "outer",
        "<anon>",
        0,
        FuncKind::Closure,
        Some(123),
        0x01,
    );
    let (k2, s2) = fs_with(
        "src/f.js",
        "outer",
        "<anon>",
        0,
        FuncKind::Closure,
        Some(456),
        0x02,
    );
    gs.insert(k1.clone(), s1);
    gs.insert(k2.clone(), s2);

    assert_ne!(k1, k2);
    assert_eq!(gs.get(&k1).unwrap().sink_caps, 0x01);
    assert_eq!(gs.get(&k2).unwrap().sink_caps, 0x02);
}

#[test]
fn interop_lookup_tolerates_missing_disambig() {
    // Interop edges written by external configuration don't know byte offsets.
    // `get_for_interop` should still find a single matching key when disambig
    // is None and the rest of the identity uniquely identifies a summary.
    let mut gs = GlobalSummaries::new();
    let (k, s) = fs_with(
        "lib.go",
        "",
        "fetch_env",
        0,
        FuncKind::Function,
        Some(7777),
        0x04,
    );
    // Go summaries are actually keyed with Lang::Go; use a distinct key here.
    let go_key = FuncKey::from_parts(
        Lang::Go,
        "lib.go",
        String::new(),
        "fetch_env",
        Some(0),
        Some(7777),
        FuncKind::Function,
    );
    let go_sum = FuncSummary {
        name: "fetch_env".into(),
        file_path: "lib.go".into(),
        lang: "go".into(),
        ..s
    };
    gs.insert(go_key, go_sum);
    let _ = k; // unused: only needed for symmetry with fs_with signature

    let interop_query = FuncKey::from_parts(
        Lang::Go,
        "lib.go",
        String::new(),
        "fetch_env",
        Some(0),
        None,
        FuncKind::Function,
    );
    let hit = gs
        .get_for_interop(&interop_query)
        .expect("interop lookup should tolerate missing disambig");
    assert_eq!(hit.sink_caps, 0x04);
}

#[test]
fn interop_lookup_returns_none_when_disambig_none_matches_many() {
    // If multiple summaries share (lang, ns, container, name, arity, kind)
    // and only disambig distinguishes them, the relaxed interop lookup must
    // return None rather than picking arbitrarily.
    let mut gs = GlobalSummaries::new();
    let mk = |disambig: u32, bits: u32| {
        let k = FuncKey::from_parts(
            Lang::Go,
            "lib.go",
            String::new(),
            "dup",
            Some(0),
            Some(disambig),
            FuncKind::Function,
        );
        let s = FuncSummary {
            name: "dup".into(),
            file_path: "lib.go".into(),
            lang: "go".into(),
            sink_caps: bits,
            disambig: Some(disambig),
            ..Default::default()
        };
        (k, s)
    };
    let (k1, s1) = mk(1, 0x01);
    let (k2, s2) = mk(2, 0x02);
    gs.insert(k1, s1);
    gs.insert(k2, s2);

    let ambiguous_query = FuncKey::from_parts(
        Lang::Go,
        "lib.go",
        String::new(),
        "dup",
        Some(0),
        None,
        FuncKind::Function,
    );
    assert!(
        gs.get_for_interop(&ambiguous_query).is_none(),
        "disambig=None must not pick arbitrarily when multiple keys match"
    );
}

// ── CalleeSite metadata ─────────────────────────────────────────────────

#[test]
fn callee_site_bare_constructor() {
    let site = CalleeSite::bare("helper");
    assert_eq!(site.name, "helper");
    assert_eq!(site.arity, None);
    assert_eq!(site.receiver, None);
    assert_eq!(site.qualifier, None);
    assert_eq!(site.ordinal, 0);
}

#[test]
fn callee_site_str_into_coercion() {
    // Tests that `"name".into()` still works for building callee lists in
    // test code, despite the field now being `Vec<CalleeSite>`.
    let v: Vec<CalleeSite> = vec!["foo".into(), "bar".into()];
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].name, "foo");
    assert_eq!(v[1].name, "bar");
}

#[test]
fn callee_site_structured_roundtrip() {
    let summary = FuncSummary {
        name: "parent".into(),
        file_path: "x.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        callees: vec![
            CalleeSite {
                name: "obj.method".into(),
                arity: Some(2),
                receiver: Some("obj".into()),
                qualifier: None,
                ordinal: 1,
                ..Default::default()
            },
            CalleeSite {
                name: "env::var".into(),
                arity: Some(1),
                receiver: None,
                qualifier: Some("env".into()),
                ordinal: 2,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: FuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.callees.len(), 2);
    assert_eq!(back.callees[0].name, "obj.method");
    assert_eq!(back.callees[0].arity, Some(2));
    assert_eq!(back.callees[0].receiver.as_deref(), Some("obj"));
    assert_eq!(back.callees[0].ordinal, 1);
    assert_eq!(back.callees[1].qualifier.as_deref(), Some("env"));
}

#[test]
fn legacy_callees_string_array_deserializes() {
    // Old on-disk rows stored callees as a plain Vec<String>.
    // The custom deserializer must lift those into CalleeSite { name, .. }
    // without other metadata so persisted indexes keep working.
    let json = r#"{
        "name": "legacy",
        "file_path": "legacy.rs",
        "lang": "rust",
        "param_count": 0,
        "param_names": [],
        "source_caps": 0,
        "sanitizer_caps": 0,
        "sink_caps": 0,
        "propagating_params": [],
        "tainted_sink_params": [],
        "callees": ["foo", "bar::baz"]
    }"#;
    let s: FuncSummary = serde_json::from_str(json).unwrap();
    assert_eq!(s.callees.len(), 2);
    assert_eq!(s.callees[0].name, "foo");
    assert_eq!(s.callees[0].arity, None);
    assert_eq!(s.callees[1].name, "bar::baz");
    assert_eq!(s.callees[1].receiver, None);
}

#[test]
fn mixed_callee_form_deserializes() {
    // Interop / partial-migration rows may mix legacy strings with
    // structured entries in the same array, deserializer accepts both.
    let json = r#"{
        "name": "mixed",
        "file_path": "m.rs",
        "lang": "rust",
        "param_count": 0,
        "param_names": [],
        "source_caps": 0,
        "sanitizer_caps": 0,
        "sink_caps": 0,
        "propagating_params": [],
        "tainted_sink_params": [],
        "callees": [
            "legacy_fn",
            {"name": "new_fn", "arity": 3, "receiver": "obj"}
        ]
    }"#;
    let s: FuncSummary = serde_json::from_str(json).unwrap();
    assert_eq!(s.callees.len(), 2);
    assert_eq!(s.callees[0].name, "legacy_fn");
    assert_eq!(s.callees[0].arity, None);
    assert_eq!(s.callees[1].name, "new_fn");
    assert_eq!(s.callees[1].arity, Some(3));
    assert_eq!(s.callees[1].receiver.as_deref(), Some("obj"));
}

// ── Rust module-path resolution (qualified Rust paths) ──────────────────

/// Helper: build a Rust summary populated with module-path + use-map fields.
fn rust_summary_with_mod(
    name: &str,
    file_path: &str,
    param_count: usize,
    module_path: Option<&str>,
    use_map: &[(&str, &str)],
    wildcards: &[&str],
    callees: Vec<CalleeSite>,
) -> FuncSummary {
    let aliases: BTreeMap<String, String> = use_map
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    FuncSummary {
        name: name.into(),
        file_path: file_path.into(),
        lang: "rust".into(),
        param_count,
        param_names: vec![],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees,
        module_path: module_path.map(str::to_string),
        rust_use_map: if aliases.is_empty() {
            None
        } else {
            Some(aliases)
        },
        rust_wildcards: if wildcards.is_empty() {
            None
        } else {
            Some(wildcards.iter().map(|s| (*s).to_string()).collect())
        },
        ..Default::default()
    }
}

#[test]
fn rust_use_map_disambiguates_same_name_across_modules() {
    // Two `validate` functions in different modules.
    let token = rust_summary_with_mod(
        "validate",
        "/proj/src/auth/token.rs",
        1,
        Some("auth::token"),
        &[],
        &[],
        vec![],
    );
    let session = rust_summary_with_mod(
        "validate",
        "/proj/src/auth/session.rs",
        1,
        Some("auth::session"),
        &[],
        &[],
        vec![],
    );
    // Caller imports crate::auth::token::validate and calls `validate(x)`.
    let caller = rust_summary_with_mod(
        "handler",
        "/proj/src/main.rs",
        0,
        Some(""),
        &[("validate", "crate::auth::token::validate")],
        &[],
        vec![CalleeSite {
            name: "validate".into(),
            arity: Some(1),
            ..Default::default()
        }],
    );

    let gs = merge_summaries(vec![token, session, caller], Some("/proj"));
    // Pull the token key back out and verify exact-one resolution.
    let caller_key = FuncKey::from_parts(
        Lang::Rust,
        "src/main.rs",
        String::new(),
        "handler",
        Some(0),
        None,
        FuncKind::Function,
    );
    let caller_sum = gs.get(&caller_key).expect("caller summary");
    let use_map = crate::rust_resolve::RustUseMap {
        aliases: caller_sum.rust_use_map.clone().unwrap_or_default(),
        wildcards: caller_sum.rust_wildcards.clone().unwrap_or_default(),
    };
    let resolution = gs.resolve_callee_key_rust(
        "validate",
        None,
        Some(1),
        &caller_key.namespace,
        Some(&use_map),
    );
    match resolution {
        CalleeResolution::Resolved(k) => {
            assert_eq!(k.namespace, "src/auth/token.rs");
            assert_eq!(k.name, "validate");
        }
        other => panic!(
            "expected token::validate to resolve uniquely, got {:?}",
            other
        ),
    }
}

#[test]
fn rust_use_map_qualified_call_via_module_alias() {
    // `use crate::auth::token;  token::validate(x);`
    let token = rust_summary_with_mod(
        "validate",
        "/proj/src/auth/token.rs",
        1,
        Some("auth::token"),
        &[],
        &[],
        vec![],
    );
    let caller = rust_summary_with_mod(
        "handler",
        "/proj/src/main.rs",
        0,
        Some(""),
        &[("token", "crate::auth::token")],
        &[],
        vec![CalleeSite {
            name: "token::validate".into(),
            arity: Some(1),
            qualifier: Some("crate::auth::token".into()),
            ..Default::default()
        }],
    );

    let gs = merge_summaries(vec![token, caller], Some("/proj"));
    let um = crate::rust_resolve::RustUseMap {
        aliases: [("token".to_string(), "crate::auth::token".to_string())]
            .into_iter()
            .collect(),
        wildcards: Vec::new(),
    };
    // The site's structured qualifier is the full `crate::auth::token`; the
    // resolver's alias map matches the first segment.
    let resolution =
        gs.resolve_callee_key_rust("validate", Some("token"), Some(1), "src/main.rs", Some(&um));
    match resolution {
        CalleeResolution::Resolved(k) => {
            assert_eq!(k.namespace, "src/auth/token.rs");
        }
        other => panic!("expected unique resolution, got {:?}", other),
    }
}

#[test]
fn rust_wildcard_import_resolves_uniquely() {
    let token = rust_summary_with_mod(
        "validate",
        "/proj/src/auth/token.rs",
        1,
        Some("auth::token"),
        &[],
        &[],
        vec![],
    );
    let caller = rust_summary_with_mod(
        "handler",
        "/proj/src/main.rs",
        0,
        Some(""),
        &[],
        &["crate::auth::token"],
        vec![CalleeSite {
            name: "validate".into(),
            arity: Some(1),
            ..Default::default()
        }],
    );

    let gs = merge_summaries(vec![token, caller], Some("/proj"));
    let um = crate::rust_resolve::RustUseMap {
        aliases: BTreeMap::new(),
        wildcards: vec!["crate::auth::token".to_string()],
    };
    let resolution =
        gs.resolve_callee_key_rust("validate", None, Some(1), "src/main.rs", Some(&um));
    match resolution {
        CalleeResolution::Resolved(k) => {
            assert_eq!(k.namespace, "src/auth/token.rs");
        }
        other => panic!("wildcard should resolve uniquely, got {:?}", other),
    }
}

#[test]
fn rust_use_map_fallback_when_absent() {
    // No use_map entry, falls through to generic same-language resolution,
    // which for an unqualified caller in the same namespace still works.
    let helper = rust_summary_with_mod("helper", "/proj/src/lib.rs", 0, Some(""), &[], &[], vec![]);
    let caller = rust_summary_with_mod(
        "caller",
        "/proj/src/lib.rs",
        0,
        Some(""),
        &[],
        &[],
        vec![CalleeSite {
            name: "helper".into(),
            arity: Some(0),
            ..Default::default()
        }],
    );

    let gs = merge_summaries(vec![helper, caller], Some("/proj"));
    let resolution = gs.resolve_callee_key_rust("helper", None, Some(0), "src/lib.rs", None);
    assert!(matches!(resolution, CalleeResolution::Resolved(_)));
}

#[test]
fn rust_use_map_ambiguous_stays_ambiguous_without_hint() {
    // Two modules define `validate`; no use-map on the caller, resolution
    // should remain Ambiguous rather than silently picking one.
    let token = rust_summary_with_mod(
        "validate",
        "/proj/src/auth/token.rs",
        1,
        Some("auth::token"),
        &[],
        &[],
        vec![],
    );
    let session = rust_summary_with_mod(
        "validate",
        "/proj/src/auth/session.rs",
        1,
        Some("auth::session"),
        &[],
        &[],
        vec![],
    );
    let caller = rust_summary_with_mod(
        "handler",
        "/proj/src/main.rs",
        0,
        Some(""),
        &[],
        &[],
        vec![CalleeSite {
            name: "validate".into(),
            arity: Some(1),
            ..Default::default()
        }],
    );
    let gs = merge_summaries(vec![token, session, caller], Some("/proj"));
    let resolution = gs.resolve_callee_key_rust("validate", None, Some(1), "src/main.rs", None);
    assert!(matches!(resolution, CalleeResolution::Ambiguous(_)));
}

// ── Serde round-trip / backward compatibility ────────────────────────────

#[test]
fn pre_rust_fields_json_deserializes_with_defaults() {
    // A summary JSON written before the Rust `module_path`/`rust_use_map`/
    // `rust_wildcards` fields existed must still deserialise cleanly with
    // all three defaulting to `None`.
    let legacy_json = r#"{
        "name": "old",
        "file_path": "src/lib.rs",
        "lang": "rust",
        "param_count": 1,
        "param_names": ["x"],
        "source_caps": 0,
        "sanitizer_caps": 0,
        "sink_caps": 0,
        "propagating_params": [0],
        "tainted_sink_params": [],
        "callees": []
    }"#;
    let s: FuncSummary = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(s.name, "old");
    assert!(s.module_path.is_none());
    assert!(s.rust_use_map.is_none());
    assert!(s.rust_wildcards.is_none());
}

#[test]
fn rust_fields_roundtrip_through_json() {
    let mut aliases = BTreeMap::new();
    aliases.insert(
        "validate".to_string(),
        "crate::auth::token::validate".to_string(),
    );
    let s = FuncSummary {
        name: "handler".into(),
        file_path: "src/main.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        module_path: Some(String::new()),
        rust_use_map: Some(aliases.clone()),
        rust_wildcards: Some(vec!["crate::auth::session".to_string()]),
        ..Default::default()
    };

    let json = serde_json::to_string(&s).unwrap();
    let back: FuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.module_path.as_deref(), Some(""));
    assert_eq!(back.rust_use_map.unwrap(), aliases);
    assert_eq!(
        back.rust_wildcards.unwrap(),
        vec!["crate::auth::session".to_string()]
    );
}

// ── Qualified-first callee resolution (adversarial) ─────────────────────
//
// Each test here stages a same-leaf-name collision that the old leaf-only
// resolver would either silently pick wrong or flag as ambiguous.  Under
// the new `CalleeQuery` path, qualified identity (receiver type /
// namespace qualifier / caller container) must win before any bare-leaf
// fallback kicks in.

fn method_summary(
    namespace: &str,
    container: &str,
    name: &str,
    arity: usize,
    sink_bits: u32,
) -> (FuncKey, FuncSummary) {
    fs_with(
        namespace,
        container,
        name,
        arity,
        FuncKind::Method,
        Some((namespace.len() + container.len() + name.len()) as u32),
        sink_bits,
    )
}

fn free_summary(
    namespace: &str,
    name: &str,
    arity: usize,
    sink_bits: u32,
) -> (FuncKey, FuncSummary) {
    fs_with(
        namespace,
        "",
        name,
        arity,
        FuncKind::Function,
        Some((namespace.len() + name.len()) as u32),
        sink_bits,
    )
}

#[test]
fn query_prefers_receiver_type_over_leaf_collision() {
    // Two classes in different files both expose `send/1`.  A free
    // function also named `send/1` sits in yet another file to make the
    // leaf-name index ambiguous.  The caller lives outside all three.
    let mut gs = GlobalSummaries::new();
    let (k_http, s_http) = method_summary("src/http.java", "HttpClient", "send", 1, 0x01);
    let (k_queue, s_queue) = method_summary("src/queue.java", "MessageQueue", "send", 1, 0x02);
    let (k_free, s_free) = free_summary("src/util.java", "send", 1, 0x04);
    gs.insert(k_http.clone(), s_http);
    gs.insert(k_queue.clone(), s_queue);
    gs.insert(k_free.clone(), s_free);

    // With `receiver_type = HttpClient`, resolution MUST land on the
    // HttpClient method even though `MessageQueue::send/1` and the free
    // function `send/1` would both match the leaf name.
    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "send",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: None,
        receiver_type: Some("HttpClient"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(resolved, CalleeResolution::Resolved(k_http.clone()));

    // Old behaviour-parity regression: `resolve_callee_key_with_container`
    // (now a thin wrapper) used to treat `MessageQueue` as an authoritative
    // qualifier that *only* picked on exact match.  The new resolver must
    // still do that, swap to `MessageQueue` and we get its method back.
    let resolved_queue = gs.resolve_callee(&CalleeQuery {
        name: "send",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: None,
        receiver_type: Some("MessageQueue"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(resolved_queue, CalleeResolution::Resolved(k_queue));
    // And the leaf-name index *does* know about the free function: no
    // hint → ambiguous (not a silent mis-resolve).
    let bare = gs.resolve_callee_key("send", Lang::Java, "src/app.java", Some(1));
    match bare {
        CalleeResolution::Ambiguous(cands) => {
            assert_eq!(cands.len(), 3);
            assert!(cands.contains(&k_http));
            assert!(cands.contains(&k_free));
        }
        other => panic!("bare leaf lookup with 3 candidates must be Ambiguous, got {other:?}"),
    }
}

#[test]
fn query_authoritative_receiver_miss_does_not_fall_through_to_leaf() {
    // When `receiver_type = HttpClient` is supplied but no
    // `HttpClient::send` exists, the resolver MUST NOT silently pick a
    // same-leaf collision in another container, that would be the
    // classic "resolved by leaf name" bug the refactor aims to prevent.
    let mut gs = GlobalSummaries::new();
    let (k_queue, s_queue) = method_summary("src/queue.java", "MessageQueue", "send", 1, 0x02);
    let (k_free, s_free) = free_summary("src/util.java", "send", 1, 0x04);
    gs.insert(k_queue.clone(), s_queue);
    gs.insert(k_free.clone(), s_free);

    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "send",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: None,
        receiver_type: Some("HttpClient"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    match resolved {
        CalleeResolution::Ambiguous(cands) => {
            // Candidates list reports the leaf-name matches so callers
            // can diagnose, but we refused to pick one of them.
            assert!(cands.contains(&k_queue));
            assert!(cands.contains(&k_free));
        }
        other => panic!(
            "authoritative receiver_type miss must return Ambiguous (never silently resolve to a \
             different container), got {other:?}"
        ),
    }
}

#[test]
fn query_namespace_qualifier_resolves_env_var_style_call() {
    // Rust / C++-style namespace qualifiers should land on the module
    // that exposes the leaf, even when same-leaf functions live in
    // unrelated modules.
    let mut gs = GlobalSummaries::new();
    let (k_env, s_env) = fs_with(
        "src/env.rs",
        "env",
        "var",
        1,
        FuncKind::Function,
        Some(1),
        0x01,
    );
    // Force the insertion to use Rust lang by shadowing fs_with's Java default.
    let k_env = FuncKey::from_parts(
        Lang::Rust,
        k_env.namespace,
        k_env.container,
        k_env.name,
        k_env.arity,
        k_env.disambig,
        k_env.kind,
    );
    let s_env = FuncSummary {
        lang: "rust".into(),
        ..s_env
    };
    let (k_other, s_other) = fs_with(
        "src/other.rs",
        "config",
        "var",
        1,
        FuncKind::Function,
        Some(2),
        0x02,
    );
    let k_other = FuncKey::from_parts(
        Lang::Rust,
        k_other.namespace,
        k_other.container,
        k_other.name,
        k_other.arity,
        k_other.disambig,
        k_other.kind,
    );
    let s_other = FuncSummary {
        lang: "rust".into(),
        ..s_other
    };
    gs.insert(k_env.clone(), s_env);
    gs.insert(k_other.clone(), s_other);

    // `env::var` → namespace_qualifier = "env" → env::var wins.
    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "var",
        caller_lang: Lang::Rust,
        caller_namespace: "src/consumer.rs",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: Some("env"),
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(resolved, CalleeResolution::Resolved(k_env.clone()));

    // `config::var` → namespace_qualifier = "config" → config::var wins.
    let resolved_cfg = gs.resolve_callee(&CalleeQuery {
        name: "var",
        caller_lang: Lang::Rust,
        caller_namespace: "src/consumer.rs",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: Some("config"),
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(resolved_cfg, CalleeResolution::Resolved(k_other));

    // Bare `var(...)` call (no qualifier) across namespaces → Ambiguous.
    let bare = gs.resolve_callee_key("var", Lang::Rust, "src/consumer.rs", Some(1));
    assert!(matches!(bare, CalleeResolution::Ambiguous(_)));
}

#[test]
fn query_caller_container_resolves_self_call() {
    // Bare `helper()` from inside `OrderService::place` must resolve to
    // the `OrderService::helper` method rather than a same-name helper
    // exposed by an unrelated class in a different file.
    let mut gs = GlobalSummaries::new();
    let (k_order, s_order) = method_summary("src/order.java", "OrderService", "helper", 0, 0xA);
    let (k_user, s_user) = method_summary("src/user.java", "UserService", "helper", 0, 0xB);
    gs.insert(k_order.clone(), s_order);
    gs.insert(k_user.clone(), s_user);

    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "helper",
        caller_lang: Lang::Java,
        caller_namespace: "src/order.java",
        caller_container: Some("OrderService"),
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(0),
    });
    assert_eq!(resolved, CalleeResolution::Resolved(k_order.clone()));

    // Swap the caller to `UserService` and we should land on its helper.
    let resolved_user = gs.resolve_callee(&CalleeQuery {
        name: "helper",
        caller_lang: Lang::Java,
        caller_namespace: "src/user.java",
        caller_container: Some("UserService"),
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(0),
    });
    assert_eq!(resolved_user, CalleeResolution::Resolved(k_user));

    // With no caller-container hint (free call from module-level code),
    // the resolver must not pick either class's helper blindly.
    let no_hint = gs.resolve_callee(&CalleeQuery {
        name: "helper",
        caller_lang: Lang::Java,
        caller_namespace: "src/main.java",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(0),
    });
    assert!(matches!(no_hint, CalleeResolution::Ambiguous(_)));
}

#[test]
fn query_leaf_same_namespace_still_resolves_intra_file_calls() {
    // Two definitions share a leaf name but live in different files.
    // A same-namespace call (intra-file) must resolve to the local one
    // without requiring any structured hint, this is the common case
    // for bare top-level function calls.
    let mut gs = GlobalSummaries::new();
    let (k_a, s_a) = free_summary("src/a.js", "helper", 1, 0x01);
    let (k_b, s_b) = free_summary("src/b.js", "helper", 1, 0x02);
    gs.insert(k_a.clone(), s_a);
    gs.insert(k_b.clone(), s_b);

    // Caller in a.js → resolves to a.js::helper.
    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "helper",
        caller_lang: Lang::Java,
        caller_namespace: "src/a.js",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(resolved, CalleeResolution::Resolved(k_a));

    // Caller in a third file → ambiguous (we refuse to guess).
    let cross = gs.resolve_callee(&CalleeQuery {
        name: "helper",
        caller_lang: Lang::Java,
        caller_namespace: "src/c.js",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    match cross {
        CalleeResolution::Ambiguous(cands) => {
            assert_eq!(cands.len(), 2);
            assert!(cands.contains(&k_b));
        }
        other => panic!("cross-file bare leaf should be Ambiguous, got {other:?}"),
    }
}

#[test]
fn query_arity_filter_is_hard() {
    // Same container and leaf, different arities, resolution must
    // honour the arity filter before any qualifier-based tie-break.
    let mut gs = GlobalSummaries::new();
    let (k_1arg, s_1arg) = method_summary("src/svc.py", "Svc", "render", 1, 0x01);
    let (k_2arg, s_2arg) = method_summary("src/svc.py", "Svc", "render", 2, 0x02);
    gs.insert(k_1arg.clone(), s_1arg);
    gs.insert(k_2arg.clone(), s_2arg);

    let one = gs.resolve_callee(&CalleeQuery {
        name: "render",
        caller_lang: Lang::Java,
        caller_namespace: "src/caller.py",
        caller_container: None,
        receiver_type: Some("Svc"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(one, CalleeResolution::Resolved(k_1arg));

    let two = gs.resolve_callee(&CalleeQuery {
        name: "render",
        caller_lang: Lang::Java,
        caller_namespace: "src/caller.py",
        caller_container: None,
        receiver_type: Some("Svc"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(2),
    });
    assert_eq!(two, CalleeResolution::Resolved(k_2arg));

    // With a non-existent arity, arity filter prunes everything and we
    // get NotFound, not a "closest match" guess.
    let mismatched = gs.resolve_callee(&CalleeQuery {
        name: "render",
        caller_lang: Lang::Java,
        caller_namespace: "src/caller.py",
        caller_container: None,
        receiver_type: Some("Svc"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(5),
    });
    match mismatched {
        CalleeResolution::NotFound | CalleeResolution::Ambiguous(_) => {}
        CalleeResolution::Resolved(k) => {
            panic!("arity mismatch must not resolve; got {k:?}")
        }
    }
}

#[test]
fn query_receiver_var_is_soft_tiebreak_not_primary() {
    // Adversarial case: a variable named "obj" exists and a class
    // happens to also be called "obj".  The old resolver used the
    // variable name as container_hint #1, which could mis-pick when
    // the qualified index had a coincidental hit.  The new resolver
    // treats `receiver_var` as a *soft* tie-break, it only fires
    // after same-namespace unique-leaf resolution fails.
    let mut gs = GlobalSummaries::new();
    let (k_same_ns, s_same_ns) = free_summary("src/app.js", "method", 1, 0xAA);
    let (k_other_class, s_other_class) = method_summary("src/other.js", "obj", "method", 1, 0xBB);
    gs.insert(k_same_ns.clone(), s_same_ns);
    gs.insert(k_other_class.clone(), s_other_class);

    // Caller lives in app.js → intra-file unique-leaf wins, regardless
    // of the variable-named `obj` coincidence in other.js.
    let intra = gs.resolve_callee(&CalleeQuery {
        name: "method",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.js",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: Some("obj"),
        arity: Some(1),
    });
    assert_eq!(intra, CalleeResolution::Resolved(k_same_ns));

    // Caller in a third file where no same-namespace match exists →
    // receiver_var tie-break fires and picks `obj::method`.
    let cross = gs.resolve_callee(&CalleeQuery {
        name: "method",
        caller_lang: Lang::Java,
        caller_namespace: "src/elsewhere.js",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: Some("obj"),
        arity: Some(1),
    });
    assert_eq!(cross, CalleeResolution::Resolved(k_other_class));
}

#[test]
fn query_qualifier_miss_refuses_to_guess_leaf() {
    // `namespace_qualifier = "Missing"` does not exist as a container.
    // We have two leaf candidates.  The resolver must NOT fall back
    // and pick one of them silently.  (It may return the leaf set
    // as Ambiguous for diagnostics.)
    let mut gs = GlobalSummaries::new();
    let (k_a, s_a) = free_summary("src/a.go", "run", 1, 0x1);
    let (k_b, s_b) = free_summary("src/b.go", "run", 1, 0x2);
    gs.insert(k_a.clone(), s_a);
    gs.insert(k_b.clone(), s_b);

    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "run",
        caller_lang: Lang::Java,
        caller_namespace: "src/caller.go",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: Some("Missing"),
        receiver_var: None,
        arity: Some(1),
    });
    match resolved {
        CalleeResolution::Ambiguous(cands) => {
            assert_eq!(cands.len(), 2);
            assert!(cands.contains(&k_a));
            assert!(cands.contains(&k_b));
        }
        CalleeResolution::Resolved(k) => {
            panic!("unresolved qualifier must not silently pick a leaf-only match; got {k:?}")
        }
        CalleeResolution::NotFound => panic!("candidates exist — should be Ambiguous not NotFound"),
    }
}

#[test]
fn legacy_wrapper_preserves_test_contract() {
    // The old `resolve_callee_key_with_container` entry point is kept as
    // a thin wrapper.  The pre-refactor tests
    // (`same_name_methods_on_different_classes_stay_distinct` and
    // `free_function_and_method_with_same_name_resolve_separately`)
    // already cover the happy paths; this test pins the *contract* of
    // the wrapper itself so we do not drift: a container hint is
    // treated as a non-authoritative namespace qualifier and falls
    // through to leaf lookup when it misses.
    let mut gs = GlobalSummaries::new();
    let (k_a, s_a) = free_summary("src/a.java", "only", 1, 0x1);
    gs.insert(k_a.clone(), s_a);

    // container_hint doesn't match any container, but the leaf name has
    // exactly one candidate, the wrapper should still resolve.
    let resolved = gs.resolve_callee_key_with_container(
        "only",
        Lang::Java,
        "src/caller.java",
        Some("NonExistent"),
        Some(1),
    );
    assert_eq!(resolved, CalleeResolution::Resolved(k_a));
}

// ── Adversarial: same-name identity collisions in the SAME file ─────────
//
// These tests target the most error-prone identity cases: two or more
// definitions that share `(lang, namespace, name, arity)` but differ in
// `container`.  The resolver must either resolve to the exact container
// target or refuse to guess, silently falling back to a same-leaf
// collision in a different container is a correctness bug, and mis-
// ordering the resolution steps can cause either false positives (wrong
// summary picked) or false negatives (missed flow because Ambiguous
// took a confident hint off the table).

#[test]
fn same_file_two_classes_same_method_typed_receiver_picks_exact() {
    // Two classes in the SAME file, both defining `run/1` with
    // incompatible security behaviour: `Safe::run` is a sanitizer-ish
    // passthrough (no sink bits) while `Unsafe::run` is a shell sink.
    // When the caller has a typed receiver (via type inference), the
    // resolver must pick the exact class, the wrong pick would either
    // miss the Unsafe sink or wrongly flag the Safe path.
    let mut gs = GlobalSummaries::new();
    let (k_safe, s_safe) = method_summary("src/app.java", "Safe", "run", 1, 0x00);
    let (k_unsafe, s_unsafe) =
        method_summary("src/app.java", "Unsafe", "run", 1, Cap::SHELL_ESCAPE.bits());
    gs.insert(k_safe.clone(), s_safe);
    gs.insert(k_unsafe.clone(), s_unsafe);

    let unsafe_call = gs.resolve_callee(&CalleeQuery {
        name: "run",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: None,
        receiver_type: Some("Unsafe"),
        namespace_qualifier: None,
        receiver_var: Some("u"),
        arity: Some(1),
    });
    assert_eq!(
        unsafe_call,
        CalleeResolution::Resolved(k_unsafe.clone()),
        "typed receiver `Unsafe` MUST land on Unsafe::run, not Safe::run"
    );

    let safe_call = gs.resolve_callee(&CalleeQuery {
        name: "run",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: None,
        receiver_type: Some("Safe"),
        namespace_qualifier: None,
        receiver_var: Some("s"),
        arity: Some(1),
    });
    assert_eq!(
        safe_call,
        CalleeResolution::Resolved(k_safe.clone()),
        "typed receiver `Safe` MUST land on Safe::run, not Unsafe::run"
    );

    // Sink-cap sanity: if the resolver ever silently swapped them the
    // cap mismatch would show up here.
    assert_eq!(gs.get(&k_safe).unwrap().sink_caps, 0x00);
    assert_eq!(
        gs.get(&k_unsafe).unwrap().sink_caps,
        Cap::SHELL_ESCAPE.bits()
    );
}

#[test]
fn same_file_two_classes_same_method_untyped_receiver_is_ambiguous_not_wrong() {
    // Same setup as above, but the caller only has a variable-name
    // receiver (no type facts).  `receiver_var` is a SOFT hint, and in
    // the common case `s`/`u` don't match any container.  The resolver
    // MUST refuse to pick one arbitrarily; returning `Safe::run` when
    // the call was `u.run(...)` would be a silent false negative of the
    // worst kind (wrong summary pickup).
    let mut gs = GlobalSummaries::new();
    let (k_safe, s_safe) = method_summary("src/app.java", "Safe", "run", 1, 0x00);
    let (k_unsafe, s_unsafe) =
        method_summary("src/app.java", "Unsafe", "run", 1, Cap::SHELL_ESCAPE.bits());
    gs.insert(k_safe.clone(), s_safe);
    gs.insert(k_unsafe.clone(), s_unsafe);

    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "run",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: Some("u"),
        arity: Some(1),
    });
    match resolved {
        CalleeResolution::Ambiguous(cands) => {
            assert!(cands.contains(&k_safe));
            assert!(cands.contains(&k_unsafe));
        }
        CalleeResolution::Resolved(k) => panic!(
            "same-file same-name two-class collision with only a soft `receiver_var` MUST NOT \
             pick a specific summary — got {k:?}"
        ),
        CalleeResolution::NotFound => {
            panic!("candidates exist in the same file — must be Ambiguous, not NotFound")
        }
    }
}

#[test]
fn same_file_free_function_and_method_bare_call_prefers_free_function() {
    // Classic "I wrote a top-level helper AND a method with the same
    // name in the same file" trap.  A bare `process()` call, no
    // receiver, no qualifier, caller outside any container, is
    // syntactically a FREE function call; the method cannot be invoked
    // this way.  The resolver MUST resolve to the free function, not
    // return Ambiguous.
    //
    // NOTE: this test was FAILING under the pre-fix resolver, which
    // returned Ambiguous because step 4's same-namespace narrowing
    // still saw two candidates and step 6 had no qualified hint to
    // tie-break on.
    let mut gs = GlobalSummaries::new();
    let (k_free, s_free) = free_summary("src/app.java", "process", 1, 0x0F);
    let (k_method, s_method) = method_summary("src/app.java", "Worker", "process", 1, 0xF0);
    gs.insert(k_free.clone(), s_free);
    gs.insert(k_method.clone(), s_method);

    // Caller is a top-level free function (caller_container = None).
    let bare = gs.resolve_callee(&CalleeQuery {
        name: "process",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: None,
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(
        bare,
        CalleeResolution::Resolved(k_free.clone()),
        "bare `process()` from a top-level caller must resolve to the FREE function \
         in the same file, not get lost in Ambiguous"
    );

    // Cap sanity: if we accidentally resolved to `Worker::process` the
    // sink caps would leak and downstream taint would flag the wrong
    // flow.  Pin the exact resolution, not just Resolved-vs-Ambiguous.
    if let CalleeResolution::Resolved(k) = bare {
        assert_eq!(gs.get(&k).unwrap().sink_caps, 0x0F);
    }
}

#[test]
fn same_file_method_calling_sibling_free_function_resolves_to_free() {
    // Variant of the previous test with the caller LIVING INSIDE a
    // class whose own container does NOT define `process`.  Bare
    // `process()` inside `Runner::kick()` must still resolve to the
    // file-local free function, not get lost in Ambiguous because the
    // caller_container hint (`Runner`) misses both candidates.
    let mut gs = GlobalSummaries::new();
    let (k_free, s_free) = free_summary("src/app.java", "process", 1, 0x0F);
    let (k_method, s_method) = method_summary("src/app.java", "Worker", "process", 1, 0xF0);
    // Runner::kick exists only so caller_container("Runner") is a real
    // container name in the global summaries.  It is NOT a candidate.
    let (k_kick, s_kick) = method_summary("src/app.java", "Runner", "kick", 0, 0x00);
    gs.insert(k_free.clone(), s_free);
    gs.insert(k_method.clone(), s_method);
    gs.insert(k_kick, s_kick);

    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "process",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: Some("Runner"),
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    match resolved {
        CalleeResolution::Resolved(k) => {
            assert_eq!(
                k, k_free,
                "bare `process()` inside Runner::kick must land on the free function; \
                 picking Worker::process would be wrong-summary pickup"
            );
        }
        // Ambiguous is also wrong: syntactically this CANNOT be
        // Worker::process (no receiver, no this in the caller's
        // container), so the resolver has enough information to pick
        // the free function.
        other => panic!(
            "bare `process()` from Runner::kick should resolve to the free function; got {other:?}"
        ),
    }
}

#[test]
fn same_file_method_calling_own_container_sibling_prefers_self_class() {
    // Inverse of the previous: caller is INSIDE `Worker::other()` and
    // calls bare `process()`.  Both a free `process` AND `Worker::process`
    // exist in the file.  The caller's own container resolution (step 3)
    // must prefer `Worker::process`, otherwise intra-class self calls
    // would get misresolved to a free function with possibly different
    // security behaviour.
    let mut gs = GlobalSummaries::new();
    let (k_free, s_free) = free_summary("src/app.java", "process", 1, 0x0F);
    let (k_method, s_method) = method_summary("src/app.java", "Worker", "process", 1, 0xF0);
    gs.insert(k_free.clone(), s_free);
    gs.insert(k_method.clone(), s_method);

    let resolved = gs.resolve_callee(&CalleeQuery {
        name: "process",
        caller_lang: Lang::Java,
        caller_namespace: "src/app.java",
        caller_container: Some("Worker"),
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(
        resolved,
        CalleeResolution::Resolved(k_method),
        "self-call from Worker::other() must resolve to Worker::process, not the free function"
    );
}

#[test]
fn same_file_nested_container_same_method_disambiguates_by_container() {
    // Two nested definitions: `Outer::foo/1` and `Outer::Inner::foo/1`
    // both live in the same file.  The fully qualified container names
    // must be distinct keys and the resolver must pick each one exactly
    // when the container hint is given.  A bug that stripped nested
    // container suffixes or used only the outermost name would collapse
    // them and mis-resolve.
    let mut gs = GlobalSummaries::new();
    let (k_outer, s_outer) = method_summary("src/nested.java", "Outer", "foo", 1, 0x01);
    let (k_inner, s_inner) = method_summary("src/nested.java", "Outer::Inner", "foo", 1, 0x02);
    gs.insert(k_outer.clone(), s_outer);
    gs.insert(k_inner.clone(), s_inner);

    // Exact qualified hint "Outer::Inner" must land on the inner one.
    let inner = gs.resolve_callee(&CalleeQuery {
        name: "foo",
        caller_lang: Lang::Java,
        caller_namespace: "src/nested.java",
        caller_container: None,
        receiver_type: Some("Outer::Inner"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(
        inner,
        CalleeResolution::Resolved(k_inner.clone()),
        "`Outer::Inner` receiver_type must pick the NESTED foo — picking `Outer::foo` would be \
         wrong-summary pickup driven by prefix collapse"
    );

    // Exact qualified hint "Outer" must land on the outer one, not the
    // nested one (nested container starts with "Outer::" but is not
    // equal to "Outer").
    let outer = gs.resolve_callee(&CalleeQuery {
        name: "foo",
        caller_lang: Lang::Java,
        caller_namespace: "src/nested.java",
        caller_container: None,
        receiver_type: Some("Outer"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    assert_eq!(
        outer,
        CalleeResolution::Resolved(k_outer),
        "`Outer` receiver_type must pick only Outer::foo — not Outer::Inner::foo via prefix match"
    );

    // Exact cap pinning, guards against merge_summaries accidentally
    // unioning caps across the two nested keys.
    assert_eq!(gs.get(&k_inner).unwrap().sink_caps, 0x02);
}

#[test]
fn same_file_same_name_different_security_behaviour_no_cap_leak() {
    // Three `validate/1` entries in the same file: a sanitizer
    // passthrough (free function), an HTML-escape sanitizer in one
    // class, and a shell-exec sink in another class.  These must end
    // up as three distinct keys with their caps preserved exactly ,
    // no merge of sink caps into the sanitizer entry, no cross-leak
    // via `by_lang_name` fallback.
    let mut gs = GlobalSummaries::new();
    let (k_free, mut s_free) = free_summary("src/val.py", "validate", 1, 0x00);
    s_free.sanitizer_caps = Cap::all().bits();
    let (k_html, mut s_html) = method_summary("src/val.py", "HtmlGuard", "validate", 1, 0x00);
    s_html.sanitizer_caps = Cap::HTML_ESCAPE.bits();
    let (k_shell, s_shell) = method_summary(
        "src/val.py",
        "ShellRunner",
        "validate",
        1,
        Cap::SHELL_ESCAPE.bits(),
    );
    gs.insert(k_free.clone(), s_free);
    gs.insert(k_html.clone(), s_html);
    gs.insert(k_shell.clone(), s_shell);

    // Each key retrieved independently must yield exactly its own caps.
    assert_eq!(gs.get(&k_free).unwrap().sink_caps, 0x00);
    assert_eq!(gs.get(&k_free).unwrap().sanitizer_caps, Cap::all().bits());
    assert_eq!(gs.get(&k_html).unwrap().sink_caps, 0x00);
    assert_eq!(
        gs.get(&k_html).unwrap().sanitizer_caps,
        Cap::HTML_ESCAPE.bits()
    );
    assert_eq!(
        gs.get(&k_shell).unwrap().sink_caps,
        Cap::SHELL_ESCAPE.bits()
    );
    assert_eq!(gs.get(&k_shell).unwrap().sanitizer_caps, 0x00);

    // Each `receiver_type` hint must land on its OWN container.
    for (hint, expected) in [("HtmlGuard", &k_html), ("ShellRunner", &k_shell)] {
        let r = gs.resolve_callee(&CalleeQuery {
            name: "validate",
            caller_lang: Lang::Java,
            caller_namespace: "src/val.py",
            caller_container: None,
            receiver_type: Some(hint),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        assert_eq!(
            r,
            CalleeResolution::Resolved(expected.clone()),
            "receiver_type `{hint}` must pick its own container's validate"
        );
    }
}

// ── Tightened-merge regression tests ────────────────────────────────────
// These guard the identity-collision split added to `insert`, `insert_ssa`,
// and `insert_body`.  Each scenario encodes an "underspecified identity"
// (typically `disambig: None` from legacy/interop/DB-loaded summaries) where
// the old code silently collapsed structurally distinct functions.

/// Build a minimal `FuncSummary` with `disambig: None`, mirrors the shape
/// produced by legacy JSON rows / interop configs that don't know byte
/// offsets.  `file_path` is left blank so namespace normalisation doesn't
/// separate the two otherwise-identical keys.
fn legacy_summary(
    file_path: &str,
    name: &str,
    param_count: usize,
    param_names: Vec<String>,
    kind: FuncKind,
    container: &str,
    sink: u32,
) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file_path.into(),
        lang: "java".into(),
        param_count,
        param_names,
        sink_caps: sink,
        container: container.into(),
        disambig: None,
        kind,
        ..Default::default()
    }
}

#[test]
fn insert_mismatched_module_path_does_not_silently_merge() {
    // Two Rust summaries with the same leaf key but different
    // `module_path` (e.g. produced by loading a stale DB alongside a
    // freshly-scanned file, or by two different scan_root anchors).
    // `module_path` is not part of `FuncKey` but identifies the defining
    // crate module; two distinct modules with the same file path relative
    // to different scan roots must stay separate.
    let mut gs = GlobalSummaries::new();
    let a = FuncSummary {
        name: "validate".into(),
        file_path: "src/lib.rs".into(),
        lang: "rust".into(),
        param_count: 1,
        param_names: vec!["x".into()],
        sink_caps: Cap::SHELL_ESCAPE.bits(),
        disambig: None,
        module_path: Some("auth::token".into()),
        ..Default::default()
    };
    let b = FuncSummary {
        name: "validate".into(),
        file_path: "src/lib.rs".into(),
        lang: "rust".into(),
        param_count: 1,
        param_names: vec!["x".into()],
        sink_caps: Cap::SQL_QUERY.bits(),
        disambig: None,
        module_path: Some("billing::invoice".into()),
        ..Default::default()
    };
    let k = a.func_key(None);
    assert_eq!(
        k,
        b.func_key(None),
        "pre-fix: both summaries would land on the same key"
    );

    gs.insert(k.clone(), a);
    gs.insert(k.clone(), b);

    let hits = gs.lookup_same_lang(Lang::Rust, "validate");
    assert_eq!(
        hits.len(),
        2,
        "different module_path summaries must stay distinct — got {hits:?}"
    );
    let auth = hits
        .iter()
        .find(|(_, s)| s.module_path.as_deref() == Some("auth::token"))
        .expect("auth::token summary preserved");
    let billing = hits
        .iter()
        .find(|(_, s)| s.module_path.as_deref() == Some("billing::invoice"))
        .expect("billing::invoice summary preserved");
    // Cross-contamination guard: the two crates must not have their
    // caps unioned, that's the observable failure mode of a silent
    // merge.
    assert_eq!(auth.1.sink_caps, Cap::SHELL_ESCAPE.bits());
    assert_eq!(billing.1.sink_caps, Cap::SQL_QUERY.bits());
    assert_eq!(auth.1.sink_caps & Cap::SQL_QUERY.bits(), 0);
    assert_eq!(billing.1.sink_caps & Cap::SHELL_ESCAPE.bits(), 0);
}

#[test]
fn insert_mismatched_kind_does_not_silently_merge() {
    // A free function and a method with the same name, arity, namespace,
    // and container ("" vs "") can't actually occur, but kind alone
    // mismatching does happen in interop configs where a getter is
    // described as a function.  Make sure the two end up distinct.
    let mut gs = GlobalSummaries::new();
    let f = legacy_summary(
        "src/a.java",
        "size",
        0,
        vec![],
        FuncKind::Function,
        "Widget",
        0,
    );
    let g = legacy_summary(
        "src/a.java",
        "size",
        0,
        vec![],
        FuncKind::Getter,
        "Widget",
        Cap::SHELL_ESCAPE.bits(),
    );
    gs.insert(f.func_key(None), f);
    gs.insert(g.func_key(None), g);

    // Two distinct keys in the same-lang index.
    let hits = gs.lookup_same_lang(Lang::Java, "size");
    assert_eq!(hits.len(), 2);
    // The getter's sink caps must not have been unioned into the
    // function, that would be a security-relevant leak.
    let func_hit = hits
        .iter()
        .find(|(k, _)| k.kind == FuncKind::Function)
        .expect("function summary kept separate");
    assert_eq!(
        func_hit.1.sink_caps, 0,
        "function's sink caps must not absorb the getter's SHELL_ESCAPE"
    );
}

#[test]
fn insert_mismatched_param_names_does_not_silently_merge() {
    // Two overloads in Java/C++ with the same arity but different
    // parameter types/names, a classic case where arity-only identity
    // collapses distinct functions.  Neither summary ships a disambig
    // because it was loaded from legacy JSON.
    let mut gs = GlobalSummaries::new();
    let a = legacy_summary(
        "src/app.java",
        "handle",
        1,
        vec!["msg".into()],
        FuncKind::Function,
        "",
        0,
    );
    let b = legacy_summary(
        "src/app.java",
        "handle",
        1,
        vec!["event".into()],
        FuncKind::Function,
        "",
        Cap::SHELL_ESCAPE.bits(),
    );
    gs.insert(a.func_key(None), a);
    gs.insert(b.func_key(None), b);

    let hits = gs.lookup_same_lang(Lang::Java, "handle");
    assert_eq!(
        hits.len(),
        2,
        "same name + arity + kind but different param_names → distinct functions"
    );
    // Exactly one carries the sink cap.
    let sinky: Vec<_> = hits
        .iter()
        .filter(|(_, s)| s.sink_caps == Cap::SHELL_ESCAPE.bits())
        .collect();
    assert_eq!(sinky.len(), 1);
}

#[test]
fn insert_synthetic_disambig_bit_set_only_for_collisions() {
    // A single legacy-style insert with `disambig: None` must NOT gain a
    // synthetic disambig, we only rekey to resolve collisions, never
    // speculatively.  This prevents downstream lookups keyed with
    // `disambig: None` from spuriously missing legitimately-single
    // summaries.
    let mut gs = GlobalSummaries::new();
    let sole = legacy_summary(
        "src/only.java",
        "alone",
        0,
        vec![],
        FuncKind::Function,
        "",
        Cap::SHELL_ESCAPE.bits(),
    );
    let key = sole.func_key(None);
    gs.insert(key.clone(), sole);
    assert_eq!(key.disambig, None);
    assert!(gs.get(&key).is_some(), "unique legacy insert keeps its key");
}

#[test]
fn insert_compatible_refinement_still_unions() {
    // Two summaries describing the same function (structurally identical
    // head, differing only on behaviour fields) must still union, the
    // tightened check doesn't regress the classic parallel-fold merge.
    let mut gs = GlobalSummaries::new();
    let a = FuncSummary {
        name: "f".into(),
        file_path: "src/x.rs".into(),
        lang: "rust".into(),
        param_count: 1,
        param_names: vec!["x".into()],
        source_caps: Cap::ENV_VAR.bits(),
        container: "".into(),
        disambig: None,
        kind: FuncKind::Function,
        ..Default::default()
    };
    let b = FuncSummary {
        name: "f".into(),
        file_path: "src/x.rs".into(),
        lang: "rust".into(),
        param_count: 1,
        param_names: vec!["x".into()],
        sink_caps: Cap::SHELL_ESCAPE.bits(),
        container: "".into(),
        disambig: None,
        kind: FuncKind::Function,
        ..Default::default()
    };
    let k = a.func_key(None);
    gs.insert(k.clone(), a);
    gs.insert(k.clone(), b);

    let merged = gs.get(&k).expect("compatible summaries still merge");
    assert_eq!(merged.source_caps, Cap::ENV_VAR.bits());
    assert_eq!(merged.sink_caps, Cap::SHELL_ESCAPE.bits());
    // Single entry, no accidental split for the compatible case.
    let hits = gs.lookup_same_lang(Lang::Rust, "f");
    assert_eq!(hits.len(), 1);
}

#[test]
fn insert_body_param_count_mismatch_rekeys() {
    // Two CalleeSsaBody instances arrive at the same FuncKey (both
    // `disambig: None`) but claim different `param_count`.  Silently
    // replacing would lose the first body and mis-route future cross-
    // file symex resolutions to the second.
    let mut gs = GlobalSummaries::new();
    let key = FuncKey::from_parts(
        Lang::Python,
        "mod.py",
        String::new(),
        "run",
        Some(2),
        None,
        FuncKind::Function,
    );
    gs.insert_body(key.clone(), make_callee_body(2, 2));
    // Incoming body with a different param_count, must not overwrite.
    gs.insert_body(key.clone(), make_callee_body(5, 4));

    // Invariant 1: the original body stays at the original key (not
    // silently replaced by the param_count=4 body).
    let head = gs.get_body(&key).expect("original 2-param body kept");
    assert_eq!(head.param_count, 2);

    // Invariant 2: the conflicting body is preserved under a synthetic
    // disambig at its own arity, not dropped.
    let base = (4u32).wrapping_mul(0x9E37_79B9);
    let synth_key = FuncKey::from_parts(
        key.lang,
        key.namespace.clone(),
        key.container.clone(),
        key.name.clone(),
        Some(4),
        Some(0x8000_0000 | (base & 0x7FFF_FFFF)),
        key.kind,
    );
    let conflicting = gs
        .get_body(&synth_key)
        .expect("the 4-param body must be preserved under a synthetic disambig key");
    assert_eq!(conflicting.param_count, 4);
}

#[test]
fn insert_ssa_arity_overflow_rekeys() {
    // Key claims arity 1, but the incoming SSA summary references
    // param index 3, structurally impossible for the same function.
    // The fix must split so the key arity invariant is preserved.
    let mut gs = GlobalSummaries::new();
    let key = FuncKey::from_parts(
        Lang::Python,
        "mod.py",
        String::new(),
        "f",
        Some(1),
        None,
        FuncKind::Function,
    );

    let legit = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        ..Default::default()
    };
    gs.insert_ssa(key.clone(), legit.clone());
    assert_eq!(
        gs.get_ssa(&key).unwrap().param_to_return,
        vec![(0, TaintTransform::Identity)]
    );

    // Bad-arity incoming summary, must not overwrite the legitimate one.
    let overflowing = SsaFuncSummary {
        param_to_return: vec![(3, TaintTransform::Identity)],
        param_to_sink: vec![(2, cap_sites(Cap::SQL_QUERY))],
        ..Default::default()
    };
    gs.insert_ssa(key.clone(), overflowing);

    // Original summary still exactly intact at the original key.
    let kept = gs.get_ssa(&key).expect("legit summary not overwritten");
    assert_eq!(kept.param_to_return, vec![(0, TaintTransform::Identity)]);
    assert!(kept.param_to_sink.is_empty());
}

/// Audit gap A.2.1.G1 reproducer: a summary whose only param-index
/// references come from synthetic SSA `Param` ops for external
/// captures (free identifiers, module imports, unresolved method
/// names) lands at the original key when no existing entry occupies
/// it.
///
/// This is the case `lower_to_ssa` produces for Java instance/static
/// methods that reference free identifiers (e.g. `f.close()` where
/// `close` is treated as an external capture, the synthetic Param 0
/// then leaks into `param_to_return`/`param_to_sink`).  Without the
/// audit-gap fix, `reconcile_ssa_summary_key` would synthesise a
/// disambig and the analysis's `summaries.get_ssa(caller_key)` lookup
/// (consuming `typed_call_receivers` at the FuncSummary-aligned key)
/// would miss.
#[test]
fn insert_ssa_arity_overflow_keeps_original_key_when_no_collision() {
    // Single-file fresh insert: no prior entry at `key` to protect, so
    // the synthetic-Param overflow is treated as the function's own
    // signal and lands at the original FuncKey.
    let mut gs = GlobalSummaries::new();
    let key = FuncKey::from_parts(
        Lang::Java,
        "Reader.java",
        "Reader",
        "read",
        Some(0),
        None,
        FuncKind::Function,
    );
    let summary = SsaFuncSummary {
        // Synthetic Param-0 for the external `close` identifier inside
        // the static `read()` body, `param_count == 0` per the source-
        // level signature.
        param_to_return: vec![(0, TaintTransform::Identity)],
        typed_call_receivers: vec![(1, "FileHandle".to_string())],
        ..Default::default()
    };
    gs.insert_ssa(key.clone(), summary.clone());

    let kept = gs
        .get_ssa(&key)
        .expect("Reader::read SSA must be reachable at the FuncSummary-aligned key");
    assert_eq!(kept.typed_call_receivers, summary.typed_call_receivers);
    // The synthetic Param-0 reference is preserved verbatim, pass-2
    // analysis still aligns it with the caller's implicit-uses
    // argument group at the same index.
    assert_eq!(kept.param_to_return, summary.param_to_return);
}

/// Companion to `insert_ssa_arity_overflow_keeps_original_key_when_no_collision`:
/// when both rounds of an iterative scan produce summaries whose
/// param-index references overflow the FuncKey arity (the same
/// synthetic-Param signal each round), the second-round insert must
/// land at the original key (last-writer-wins for the same function),
/// not split off into a synthetic disambig.
#[test]
fn insert_ssa_arity_overflow_iterative_rescan_stays_at_original_key() {
    let mut gs = GlobalSummaries::new();
    let key = FuncKey::from_parts(
        Lang::Java,
        "Reader.java",
        "Reader",
        "read",
        Some(0),
        None,
        FuncKind::Function,
    );
    let round1 = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        typed_call_receivers: vec![(1, "FileHandle".to_string())],
        ..Default::default()
    };
    gs.insert_ssa(key.clone(), round1);

    // Iteration 2 of the scan loop produces the same shape with
    // refined typed_call_receivers (e.g. a new constructor type
    // discovered cross-file).
    let round2 = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        typed_call_receivers: vec![(1, "FileHandle".to_string()), (2, "Cache".to_string())],
        ..Default::default()
    };
    gs.insert_ssa(key.clone(), round2.clone());

    let kept = gs
        .get_ssa(&key)
        .expect("iterative-rescan summary must stay at the original key");
    assert_eq!(kept.typed_call_receivers, round2.typed_call_receivers);
    assert_eq!(kept.param_to_return, round2.param_to_return);
}

// ── Primary sink-location attribution, SinkSite round-trips ────────────

#[test]
fn sink_site_serde_round_trip_solo() {
    let site = SinkSite {
        file_rel: "src/auth/token.rs".into(),
        line: 42,
        col: 9,
        snippet: "Command::new(\"sh\").arg(cmd).status()".into(),
        cap: Cap::CODE_EXEC | Cap::SHELL_ESCAPE,
        from_chain: false,
    };
    let json = serde_json::to_string(&site).unwrap();
    let back: SinkSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

#[test]
fn sink_site_serde_round_trip_cap_only_defaults() {
    // Extraction paths without tree access produce cap-only sites.  The
    // `skip_serializing_if` default attributes let the JSON drop empty
    // fields, and deserialisation must recover the same value.
    let site = SinkSite::cap_only(Cap::SQL_QUERY);
    let json = serde_json::to_string(&site).unwrap();
    // Zero/empty fields are dropped by `skip_serializing_if`.
    assert!(!json.contains("\"line\""));
    assert!(!json.contains("\"col\""));
    assert!(!json.contains("\"file_rel\""));
    assert!(!json.contains("\"snippet\""));
    let back: SinkSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

#[test]
fn ssa_summary_serde_round_trip_with_sink_sites() {
    use smallvec::smallvec;
    let site_a = SinkSite {
        file_rel: "db.py".into(),
        line: 10,
        col: 4,
        snippet: "cursor.execute(sql)".into(),
        cap: Cap::SQL_QUERY,
        from_chain: false,
    };
    let site_b = SinkSite {
        file_rel: "exec.py".into(),
        line: 33,
        col: 12,
        snippet: "subprocess.call(cmd, shell=True)".into(),
        cap: Cap::CODE_EXEC | Cap::SHELL_ESCAPE,
        from_chain: false,
    };
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![
            (0, smallvec![site_a.clone(), site_b.clone()]),
            (1, smallvec![site_b.clone()]),
        ],
        source_caps: Cap::empty(),
        ..Default::default()
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);

    // Cap-derivation helpers still produce the expected unions.
    let caps = back.param_to_sink_caps();
    assert_eq!(caps.len(), 2);
    assert!(
        caps.iter()
            .any(|&(i, c)| i == 0 && c == (site_a.cap | site_b.cap))
    );
    assert!(caps.iter().any(|&(i, c)| i == 1 && c == site_b.cap));
    assert_eq!(back.total_param_sink_caps(), site_a.cap | site_b.cap);
}

#[test]
fn ssa_summary_deserialize_legacy_param_to_sink_missing_defaults_empty() {
    // Legacy summaries omitted the new field entirely.  The
    // `#[serde(default)]` attribute must carry the missing field through as
    // an empty vec rather than erroring out.
    let json = r#"{
        "param_to_return": [],
        "source_caps": 0
    }"#;
    let back: SsaFuncSummary = serde_json::from_str(json).unwrap();
    assert!(back.param_to_sink.is_empty());
    assert_eq!(back.total_param_sink_caps(), Cap::empty());
}

#[test]
fn func_summary_deserialize_legacy_param_to_sink_missing_defaults_empty() {
    let json = r#"{
        "name": "legacy",
        "file_path": "app.py",
        "lang": "python",
        "param_count": 1,
        "param_names": ["data"],
        "source_caps": 0,
        "sanitizer_caps": 0,
        "sink_caps": 0,
        "tainted_sink_params": []
    }"#;
    let back: FuncSummary = serde_json::from_str(json).unwrap();
    assert!(back.param_to_sink.is_empty());
}

#[test]
fn merge_unions_sink_sites_with_dedup() {
    use smallvec::smallvec;
    let key = FuncKey::from_parts(
        Lang::Python,
        "svc.py",
        String::new(),
        "run",
        Some(1),
        None,
        FuncKind::Function,
    );

    let site_a = SinkSite {
        file_rel: "svc.py".into(),
        line: 10,
        col: 1,
        snippet: "execute(sql)".into(),
        cap: Cap::SQL_QUERY,
        from_chain: false,
    };
    let site_b = SinkSite {
        file_rel: "svc.py".into(),
        line: 20,
        col: 4,
        snippet: "os.system(cmd)".into(),
        cap: Cap::CODE_EXEC,
        from_chain: false,
    };

    let mut left = FuncSummary {
        name: "run".into(),
        file_path: "svc.py".into(),
        lang: "python".into(),
        param_count: 1,
        param_names: vec!["x".into()],
        param_to_sink: vec![(0, smallvec![site_a.clone()])],
        ..Default::default()
    };
    let right = FuncSummary {
        name: "run".into(),
        file_path: "svc.py".into(),
        lang: "python".into(),
        param_count: 1,
        param_names: vec!["x".into()],
        // Mix a duplicate of site_a (same file/line/col/cap) with a new site.
        param_to_sink: vec![(0, smallvec![site_a.clone(), site_b.clone()])],
        ..Default::default()
    };

    let mut gs = GlobalSummaries::new();
    gs.insert(key.clone(), left.clone());
    gs.insert(key.clone(), right);

    let merged = gs.get(&key).unwrap();
    assert_eq!(merged.param_to_sink.len(), 1);
    let (_, sites) = &merged.param_to_sink[0];
    // Exactly two distinct sites survive; the duplicate was deduped.
    assert_eq!(sites.len(), 2);
    assert!(sites.iter().any(|s| s.dedup_key() == site_a.dedup_key()));
    assert!(sites.iter().any(|s| s.dedup_key() == site_b.dedup_key()));

    // Idempotent: re-inserting the original left introduces no new sites.
    left.param_to_sink = vec![(0, smallvec![site_a.clone()])];
    gs.insert(key.clone(), left);
    let merged = gs.get(&key).unwrap();
    assert_eq!(merged.param_to_sink[0].1.len(), 2);
}

// ── Per-return-path decomposition ───────────────────────────────────────

use super::ssa_summary::{
    MAX_RETURN_PATHS, ReturnPathTransform, merge_return_paths, union_param_return_paths,
};

fn rpt(transform: TaintTransform, hash: u64, kt: u8, kf: u8) -> ReturnPathTransform {
    ReturnPathTransform {
        transform,
        path_predicate_hash: hash,
        known_true: kt,
        known_false: kf,
        abstract_contribution: None,
    }
}

#[test]
fn cf4_return_path_transform_serde_round_trip() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],
        receiver_to_return: None,
        receiver_to_sink: Cap::empty(),
        abstract_transfer: vec![],
        param_return_paths: vec![(
            0,
            smallvec![
                rpt(TaintTransform::Identity, 0x1234, 0b001, 0),
                rpt(
                    TaintTransform::StripBits(Cap::HTML_ESCAPE),
                    0x5678,
                    0,
                    0b010
                ),
            ],
        )],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        confines_path_params: smallvec::SmallVec::new(),
        asserts_path_confined_params: Default::default(),
        result_reject_guard_params: Default::default(),
        sanitizes_open_redirect_return: false,
        confines_path_return: false,
        param_to_gate_filters: vec![],
        entry_kind: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    // Missing-field backwards compat: older JSON without `param_return_paths`
    // deserialises cleanly with an empty vector.
    let legacy = r#"{"param_to_return":[],"source_caps":0}"#;
    let legacy_back: SsaFuncSummary = serde_json::from_str(legacy).unwrap();
    assert!(legacy_back.param_return_paths.is_empty());
}

#[test]
fn cf4_merge_return_paths_dedup_by_key() {
    let mut existing: SmallVec<[ReturnPathTransform; 2]> = SmallVec::new();
    let incoming = [
        rpt(TaintTransform::Identity, 1, 0, 0),
        rpt(TaintTransform::StripBits(Cap::HTML_ESCAPE), 2, 0, 0),
        rpt(TaintTransform::Identity, 1, 0, 0), // dup of first
    ];
    merge_return_paths(&mut existing, &incoming);
    assert_eq!(existing.len(), 2, "duplicate path hash+transform collapsed");
    assert!(
        existing
            .iter()
            .any(|e| matches!(e.transform, TaintTransform::Identity) && e.path_predicate_hash == 1)
    );
    assert!(existing.iter().any(
        |e| matches!(&e.transform, TaintTransform::StripBits(b) if *b == Cap::HTML_ESCAPE)
            && e.path_predicate_hash == 2
    ));
}

#[test]
fn cf4_merge_return_paths_caps_at_max() {
    let mut existing: SmallVec<[ReturnPathTransform; 2]> = SmallVec::new();
    let many: Vec<ReturnPathTransform> = (0..(MAX_RETURN_PATHS as u64 + 3))
        .map(|i| rpt(TaintTransform::StripBits(Cap::HTML_ESCAPE), i + 10, 0, 0))
        .collect();
    merge_return_paths(&mut existing, &many);
    assert_eq!(
        existing.len(),
        1,
        "overflow collapses to a single Top-predicate entry"
    );
    // Joined entry has no predicate gate (hash=0) and conservatively takes
    // the intersection of all strip bits, which here is HTML_ESCAPE.
    let joined = &existing[0];
    assert_eq!(joined.path_predicate_hash, 0);
    assert!(matches!(
        &joined.transform,
        TaintTransform::StripBits(b) if *b == Cap::HTML_ESCAPE
    ));
}

#[test]
fn cf4_merge_return_paths_overflow_with_mixed_kinds() {
    let mut existing: SmallVec<[ReturnPathTransform; 2]> = SmallVec::new();
    let mut many: Vec<ReturnPathTransform> = (0..(MAX_RETURN_PATHS as u64 + 1))
        .map(|i| rpt(TaintTransform::StripBits(Cap::HTML_ESCAPE), i + 10, 0, 0))
        .collect();
    // One identity path forces the join to degrade to Identity (nothing
    // stripped on every path).
    many.push(rpt(TaintTransform::Identity, 99, 0, 0));
    merge_return_paths(&mut existing, &many);
    assert_eq!(existing.len(), 1);
    assert!(matches!(existing[0].transform, TaintTransform::Identity));
}

#[test]
fn cf4_merge_return_paths_joins_abstract_contribution_on_collision() {
    use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, PathFact, StringFact};

    let av_a = AbstractValue {
        interval: IntervalFact::exact(0),
        string: StringFact::top(),
        bits: BitFact::top(),
        path: PathFact::top(),
    };
    let av_b = AbstractValue {
        interval: IntervalFact::exact(10),
        string: StringFact::top(),
        bits: BitFact::top(),
        path: PathFact::top(),
    };

    let mut first = rpt(TaintTransform::Identity, 42, 0, 0);
    first.abstract_contribution = Some(av_a.clone());
    let mut second = rpt(TaintTransform::Identity, 42, 0, 0);
    second.abstract_contribution = Some(av_b.clone());

    let mut existing: SmallVec<[ReturnPathTransform; 2]> = SmallVec::new();
    merge_return_paths(&mut existing, &[first]);
    merge_return_paths(&mut existing, &[second]);
    assert_eq!(existing.len(), 1, "same key, merged");
    // The abstract_contribution is the join of the two inputs.
    let joined = existing[0].abstract_contribution.as_ref().unwrap();
    let expected = av_a.join(&av_b);
    assert_eq!(joined, &expected);
}

#[test]
fn cf4_union_param_return_paths_by_index() {
    let mut existing: Vec<(usize, SmallVec<[ReturnPathTransform; 2]>)> =
        vec![(0, smallvec![rpt(TaintTransform::Identity, 1, 0, 0)])];
    let incoming: Vec<(usize, SmallVec<[ReturnPathTransform; 2]>)> = vec![
        (
            0,
            smallvec![rpt(TaintTransform::StripBits(Cap::HTML_ESCAPE), 2, 0, 0)],
        ),
        (1, smallvec![rpt(TaintTransform::Identity, 3, 0, 0)]),
    ];
    union_param_return_paths(&mut existing, &incoming);
    assert_eq!(existing.len(), 2);
    let (_, p0) = existing.iter().find(|(i, _)| *i == 0).unwrap();
    assert_eq!(p0.len(), 2, "per-param merge preserves both predicates");
    let (_, p1) = existing.iter().find(|(i, _)| *i == 1).unwrap();
    assert_eq!(p1.len(), 1);
}

#[test]
fn cf4_ssa_summary_fits_arity_keeps_out_of_range_path_idx_at_original_key() {
    // A path whose param index exceeds the key's arity is treated as a
    // synthetic external-capture artefact (audit gap A.2.1.G1, see
    // `project_typed_callgraph_audit_gap_ssa_disambig.md`).  When no
    // existing entry sits at the key, `insert_ssa` keeps the (untrimmed)
    // summary at the original key so the SSA FuncKey stays aligned with
    // the matching FuncSummary FuncKey, the analysis's
    // `summaries.get_ssa(caller_key)` lookup (consuming
    // `typed_call_receivers`) depends on this alignment.
    let bad = SsaFuncSummary {
        param_return_paths: vec![(5, smallvec![rpt(TaintTransform::Identity, 1, 0, 0)])],
        ..Default::default()
    };
    let key = FuncKey::from_parts(
        Lang::Rust,
        "test.rs",
        String::new(),
        "helper",
        Some(2), // too small for idx 5, synthetic-Param marker
        None,
        FuncKind::Function,
    );
    let mut gs = GlobalSummaries::new();
    gs.insert_ssa(key.clone(), bad);
    let kept = gs
        .get_ssa(&key)
        .expect("synthetic-Param summary inserted at original key");
    assert_eq!(kept.param_return_paths.len(), 1);
    assert_eq!(kept.param_return_paths[0].0, 5);
}

// ── Parameter-granularity points-to summary ─────────────────────────────

#[test]
fn cf6_ssa_summary_serde_round_trip_with_points_to() {
    use crate::summary::points_to::{AliasKind, AliasPosition, PointsToSummary};

    let mut pts = PointsToSummary::empty();
    pts.insert(
        AliasPosition::Param(0),
        AliasPosition::Param(1),
        AliasKind::MayAlias,
    );
    pts.insert(
        AliasPosition::Param(0),
        AliasPosition::Return,
        AliasKind::MayAlias,
    );

    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        points_to: pts.clone(),
        ..Default::default()
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert_eq!(back.points_to, pts);
}

#[test]
fn cf6_ssa_summary_legacy_json_without_points_to_deserialises() {
    // Older on-disk JSON predates points-to tracking.  The serde(default) on
    // `points_to` must let those rows load cleanly with an empty
    // alias graph.
    let legacy = r#"{
        "param_to_return": [[0, "Identity"]],
        "source_caps": 0,
        "param_to_sink": []
    }"#;
    let back: SsaFuncSummary = serde_json::from_str(legacy).unwrap();
    assert!(back.points_to.edges.is_empty());
    assert!(!back.points_to.overflow);
}

#[test]
fn cf6_ssa_summary_fits_arity_keeps_out_of_range_points_to_idx_at_original_key() {
    // Same arity-overflow handling as `cf4_ssa_summary_fits_arity_*`
    // for the points-to channel: when the summary references a
    // synthetic-Param index beyond `key.arity` and no existing entry
    // occupies the key, `insert_ssa` preserves the FuncKey-aligned
    // identity by inserting at the original key (audit gap A.2.1.G1).
    use crate::summary::points_to::{AliasKind, AliasPosition, PointsToSummary};
    let mut pts = PointsToSummary::empty();
    pts.insert(
        AliasPosition::Param(7),
        AliasPosition::Return,
        AliasKind::MayAlias,
    );
    let bad = SsaFuncSummary {
        points_to: pts,
        ..Default::default()
    };
    let key = FuncKey::from_parts(
        Lang::Rust,
        "test.rs",
        String::new(),
        "helper",
        Some(2),
        None,
        FuncKind::Function,
    );
    let mut gs = GlobalSummaries::new();
    gs.insert_ssa(key.clone(), bad);
    let kept = gs
        .get_ssa(&key)
        .expect("synthetic-Param points_to summary inserted at original key");
    assert_eq!(kept.points_to.max_param_index(), Some(7));
}

/// two `findById`
/// definitions on different containers must remain structurally
/// disjoint after [`merge_summaries`], no cap union may leak
/// across them.  The FuncKey identity model already keys on
/// `(lang, namespace, container, name, arity, ...)` so this is
/// supposed to be true today; the test pins it down so a future
/// refactor can't silently widen the merge granularity.
///
/// Concretely: `Repository::findById` is parameterised (no
/// `SQL_QUERY` sink cap), `UnsafeCache::findById` runs a string-
/// concatenated query (carries `Cap::SQL_QUERY`).  After merge,
/// each FuncKey must own only its own caps, Repository must NOT
/// inherit Cache's `SQL_QUERY` bit.
#[test]
fn cross_file_devirt_does_not_union_unrelated_findbyids() {
    use crate::labels::Cap;
    use crate::symbol::FuncKey;

    fn method_summary(name: &str, container: &str, file: &str, sink_caps: u32) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            file_path: file.into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["id".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: if sink_caps != 0 { vec![0] } else { vec![] },
            callees: vec![],
            container: container.into(),
            ..Default::default()
        }
    }

    let safe_repo = method_summary("findById", "Repository", "src/repo.rs", 0);
    let unsafe_cache = method_summary(
        "findById",
        "UnsafeCache",
        "src/cache.rs",
        Cap::SQL_QUERY.bits(),
    );

    let gs = merge_summaries(vec![safe_repo, unsafe_cache], None);

    // Two distinct keys must coexist, no merge collision.
    let repo_key = FuncKey::from_parts(
        Lang::Rust,
        "src/repo.rs",
        "Repository",
        "findById",
        Some(1),
        None,
        FuncKind::Function,
    );
    let cache_key = FuncKey::from_parts(
        Lang::Rust,
        "src/cache.rs",
        "UnsafeCache",
        "findById",
        Some(1),
        None,
        FuncKind::Function,
    );

    let repo_sum = gs.get(&repo_key).expect("Repository::findById missing");
    let cache_sum = gs.get(&cache_key).expect("UnsafeCache::findById missing");

    // Sink caps stay on their own owner, the whole point of
    // devirtualisation.  Repository must not have inherited the
    // SQL_QUERY bit from UnsafeCache.
    assert_eq!(
        repo_sum.sink_caps, 0,
        "Repository::findById inherited a sink cap from UnsafeCache::findById — \
         the per-FuncKey identity model has been broken (sink_caps bits = {:#x})",
        repo_sum.sink_caps,
    );
    assert_eq!(
        cache_sum.sink_caps,
        Cap::SQL_QUERY.bits(),
        "UnsafeCache::findById lost its own sink cap during merge"
    );
    // Same invariant on tainted_sink_params, must not bleed across.
    assert!(
        repo_sum.tainted_sink_params.is_empty(),
        "Repository::findById inherited tainted_sink_params from UnsafeCache: {:?}",
        repo_sum.tainted_sink_params,
    );
    assert_eq!(cache_sum.tainted_sink_params, vec![0]);
}

/// Cross-file router-dep resolution: parent `__init__.py` declares
/// `Security(...)` deps on a router and lifts them onto a child via
/// `<parent>.include_router(<child_module>.<child_var>, ...)`.  The
/// resolution must produce a `<child_var> → Vec<(CallSite, scoped)>`
/// map for the child file's `module_id`, and absent edges must yield
/// empty.
#[test]
fn resolve_cross_file_router_deps_lifts_parent_security_dep_onto_child_router() {
    use crate::auth_analysis::model::CallSite;
    use crate::auth_analysis::router_facts::{PerFileRouterFacts, RouterIncludeEdge};

    let mut gs = GlobalSummaries::new();
    // Parent (__init__.py) declares scoped Security on `authenticated_router`
    // and emits two include_router edges (task_instances + dag_runs).
    let parent_callsite = CallSite {
        name: "require_auth".into(),
        args: Vec::new(),
        span: (0, 0),
        args_value_refs: Vec::new(),
    };
    let mut parent_facts = PerFileRouterFacts::default();
    parent_facts.local_router_deps.insert(
        "authenticated_router".into(),
        vec![(parent_callsite.clone(), true)],
    );
    parent_facts.include_router_edges.push(RouterIncludeEdge {
        parent_var: "authenticated_router".into(),
        child_module_id: "task_instances".into(),
        child_var: "router".into(),
        child_local: false,
    });
    parent_facts.include_router_edges.push(RouterIncludeEdge {
        parent_var: "authenticated_router".into(),
        child_module_id: "dag_runs".into(),
        child_var: "router".into(),
        child_local: false,
    });
    gs.insert_router_facts("routes::__init__".into(), parent_facts);

    // Child (task_instances.py) declares a bare router → expects to
    // inherit the parent's deps via the cross-file resolution.
    gs.insert_router_facts("task_instances".into(), PerFileRouterFacts::default());

    // Resolve for task_instances → should get one entry under `router`
    // carrying the require_auth (scoped=true) dep.
    let resolved = gs.resolve_cross_file_router_deps("task_instances");
    let deps = resolved.get("router").expect("router child resolved");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].0.name, "require_auth");
    assert!(deps[0].1, "scoped flag preserved");

    // dag_runs has the same parent → same lift.
    let resolved_dag = gs.resolve_cross_file_router_deps("dag_runs");
    assert_eq!(resolved_dag.get("router").map(|v| v.len()), Some(1));

    // Unrelated module → no lift.
    let resolved_other = gs.resolve_cross_file_router_deps("nonexistent");
    assert!(resolved_other.is_empty());
}

/// Edge: parent without local deps for the named var emits nothing —
/// the resolver requires both an edge AND a non-empty parent dep list.
#[test]
fn resolve_cross_file_router_deps_skips_edges_with_no_parent_deps() {
    use crate::auth_analysis::router_facts::{PerFileRouterFacts, RouterIncludeEdge};

    let mut gs = GlobalSummaries::new();
    let mut parent = PerFileRouterFacts::default();
    parent.include_router_edges.push(RouterIncludeEdge {
        parent_var: "ghost_router".into(),
        child_module_id: "child".into(),
        child_var: "router".into(),
        child_local: false,
    });
    gs.insert_router_facts("parent".into(), parent);

    let resolved = gs.resolve_cross_file_router_deps("child");
    assert!(resolved.is_empty());
}

/// Multiple parents declaring different deps for the same child
/// accumulate without duplication.  Same dep declared twice (one
/// from each parent) must dedup by (callee.name, scoped).
#[test]
fn resolve_cross_file_router_deps_dedups_duplicate_parent_deps() {
    use crate::auth_analysis::model::CallSite;
    use crate::auth_analysis::router_facts::{PerFileRouterFacts, RouterIncludeEdge};

    let cs = CallSite {
        name: "require_auth".into(),
        args: Vec::new(),
        span: (0, 0),
        args_value_refs: Vec::new(),
    };
    let mut gs = GlobalSummaries::new();

    // Parent A: include_router(child.router) with `require_auth` dep.
    let mut p_a = PerFileRouterFacts::default();
    p_a.local_router_deps
        .insert("router_a".into(), vec![(cs.clone(), true)]);
    p_a.include_router_edges.push(RouterIncludeEdge {
        parent_var: "router_a".into(),
        child_module_id: "child".into(),
        child_var: "router".into(),
        child_local: false,
    });
    gs.insert_router_facts("parent_a".into(), p_a);

    // Parent B: SAME dep, different parent file.
    let mut p_b = PerFileRouterFacts::default();
    p_b.local_router_deps
        .insert("router_b".into(), vec![(cs, true)]);
    p_b.include_router_edges.push(RouterIncludeEdge {
        parent_var: "router_b".into(),
        child_module_id: "child".into(),
        child_var: "router".into(),
        child_local: false,
    });
    gs.insert_router_facts("parent_b".into(), p_b);

    let resolved = gs.resolve_cross_file_router_deps("child");
    let deps = resolved.get("router").expect("router resolved");
    assert_eq!(deps.len(), 1, "duplicate (callee, scoped) deduplicated");
}

/// Transitive chain: `main.py` declares `app_router =
/// APIRouter(dependencies=[Security(require_auth)])` and includes
/// `v1.router`; `v1.py` declares a bare `router` (NO deps) and includes
/// `items.router`; `items.py` declares a bare `router`.  FastAPI lifts
/// the grandparent's Security dep all the way onto `items.router`'s
/// routes even though the intermediate `v1.router` declares nothing.
/// The resolver must walk the two-hop chain (single-hop would miss it).
#[test]
fn resolve_cross_file_router_deps_transitive_chain_lifts_grandparent_deps() {
    use crate::auth_analysis::model::CallSite;
    use crate::auth_analysis::router_facts::{PerFileRouterFacts, RouterIncludeEdge};

    let cs = CallSite {
        name: "require_auth".into(),
        args: Vec::new(),
        span: (0, 0),
        args_value_refs: Vec::new(),
    };
    let mut gs = GlobalSummaries::new();

    // Grandparent: main.py, app_router carries the Security dep + edge to v1.
    let mut main_facts = PerFileRouterFacts::default();
    main_facts
        .local_router_deps
        .insert("app_router".into(), vec![(cs.clone(), true)]);
    main_facts.include_router_edges.push(RouterIncludeEdge {
        parent_var: "app_router".into(),
        child_module_id: "v1".into(),
        child_var: "router".into(),
        child_local: false,
    });
    gs.insert_router_facts("/proj/main.py".into(), main_facts);

    // Intermediate: v1.py, bare router (no deps) + edge to items.
    let mut v1_facts = PerFileRouterFacts::default();
    v1_facts.include_router_edges.push(RouterIncludeEdge {
        parent_var: "router".into(),
        child_module_id: "items".into(),
        child_var: "router".into(),
        child_local: false,
    });
    gs.insert_router_facts("/proj/v1.py".into(), v1_facts);

    // Leaf: items.py, bare router, no edges.
    gs.insert_router_facts("/proj/items.py".into(), PerFileRouterFacts::default());

    // items.router inherits the grandparent's Security dep transitively.
    let resolved = gs.resolve_cross_file_router_deps("items");
    let deps = resolved
        .get("router")
        .expect("items.router inherits grandparent dep");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].0.name, "require_auth");
    assert!(deps[0].1, "scoped flag preserved through the chain");

    // The intermediate v1.router also inherits the grandparent dep.
    let resolved_v1 = gs.resolve_cross_file_router_deps("v1");
    assert_eq!(resolved_v1.get("router").map(|v| v.len()), Some(1));
}

/// Same-file bare-identifier lift: `app.py` declares
/// `outer = APIRouter(dependencies=[Security(require_auth)])` then
/// `outer.include_router(inner_router)`.  The bare-identifier edge must
/// lift `outer`'s deps onto `inner_router` — the in-file router-dep map
/// alone does not model `include_router` propagation, so this closes the
/// same-file bare-child gap.
#[test]
fn resolve_cross_file_router_deps_local_bare_identifier_edge_lifts_within_file() {
    use crate::auth_analysis::model::CallSite;
    use crate::auth_analysis::router_facts::{PerFileRouterFacts, RouterIncludeEdge};

    let cs = CallSite {
        name: "require_auth".into(),
        args: Vec::new(),
        span: (0, 0),
        args_value_refs: Vec::new(),
    };
    let mut gs = GlobalSummaries::new();

    let mut app = PerFileRouterFacts::default();
    app.local_router_deps
        .insert("outer".into(), vec![(cs, true)]);
    app.include_router_edges.push(RouterIncludeEdge {
        parent_var: "outer".into(),
        child_module_id: String::new(),
        child_var: "inner_router".into(),
        child_local: true,
    });
    gs.insert_router_facts("/proj/app.py".into(), app);

    let resolved = gs.resolve_cross_file_router_deps("app");
    let deps = resolved
        .get("inner_router")
        .expect("inner_router inherits outer's dep via local include_router");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].0.name, "require_auth");
}

/// Cycle safety: `a.include_router(b); b.include_router(a)` (both bare
/// same-file edges) must terminate.  The DFS visited-set guard collapses
/// the cycle; `a`'s deps still lift onto `b` and vice versa.
#[test]
fn resolve_cross_file_router_deps_cycle_terminates() {
    use crate::auth_analysis::model::CallSite;
    use crate::auth_analysis::router_facts::{PerFileRouterFacts, RouterIncludeEdge};

    let cs = CallSite {
        name: "require_auth".into(),
        args: Vec::new(),
        span: (0, 0),
        args_value_refs: Vec::new(),
    };
    let mut gs = GlobalSummaries::new();

    let mut c = PerFileRouterFacts::default();
    c.local_router_deps.insert("a".into(), vec![(cs, true)]);
    c.include_router_edges.push(RouterIncludeEdge {
        parent_var: "a".into(),
        child_module_id: String::new(),
        child_var: "b".into(),
        child_local: true,
    });
    c.include_router_edges.push(RouterIncludeEdge {
        parent_var: "b".into(),
        child_module_id: String::new(),
        child_var: "a".into(),
        child_local: true,
    });
    gs.insert_router_facts("/proj/c.py".into(), c);

    let resolved = gs.resolve_cross_file_router_deps("c");
    // Cycle: `a`'s dep reaches `b` (a is b's parent), and `a` also
    // inherits it back through `b` (b's ancestry loops to a).  The
    // visited-set guard makes the union idempotent, so each var carries
    // exactly one copy of the dep and the walk terminates.
    assert_eq!(resolved.get("b").map(|v| v.len()), Some(1));
    assert_eq!(resolved.get("a").map(|v| v.len()), Some(1));
}

// ── the analysis ────────────────────
//
// `GlobalSummaries::resolve_callee_widened` is the runtime counterpart of
// the call-graph builder's `TypeHierarchyIndex::resolve_with_hierarchy`.
// These tests pin the contract that *every* concrete implementer is
// reachable when the receiver type is statically a super-class / trait /
// interface, with the explicit fall-throughs that preserve today's
// behaviour when no fan-out applies.
mod hierarchy_widened_tests {
    use super::*;

    /// Build a minimal `(FuncKey, FuncSummary)` for a method on the
    /// given container with optional `hierarchy_edges` carried through.
    fn java_method(
        namespace: &str,
        container: &str,
        name: &str,
        arity: usize,
        sink_bits: u32,
        hierarchy_edges: Vec<(String, String)>,
    ) -> (FuncKey, FuncSummary) {
        let (key, mut summary) = fs_with(
            namespace,
            container,
            name,
            arity,
            FuncKind::Method,
            Some((namespace.len() + container.len() + name.len()) as u32),
            sink_bits,
        );
        summary.hierarchy_edges = hierarchy_edges;
        (key, summary)
    }

    /// A1, no hierarchy installed.  Widening collapses to today's
    /// single-result behaviour: one key in / one key out.
    #[test]
    fn widened_without_hierarchy_returns_single_resolved() {
        let mut gs = GlobalSummaries::new();
        let (k, s) = java_method("src/http.java", "HttpClient", "send", 1, 0x01, vec![]);
        gs.insert(k.clone(), s);

        // Hierarchy is intentionally NOT installed.
        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "send",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("HttpClient"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        assert_eq!(widened, vec![k]);
    }

    /// A2, hierarchy installed but the receiver type has no recorded
    /// sub-types.  Falls through to today's single-result behaviour.
    #[test]
    fn widened_no_subtypes_returns_single() {
        let mut gs = GlobalSummaries::new();
        let (k, s) = java_method("src/http.java", "HttpClient", "send", 1, 0x01, vec![]);
        gs.insert(k.clone(), s);
        gs.install_hierarchy();

        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "send",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("HttpClient"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        assert_eq!(widened, vec![k]);
    }

    /// A3, hierarchy with one sub-type implementer.  Widening returns
    /// both the direct receiver match and the sub-type's match.
    #[test]
    fn widened_one_subtype_returns_two_keys() {
        let mut gs = GlobalSummaries::new();
        // Carrier: ILogger -> ConsoleLogger edge.
        let (k_iface, s_iface) = java_method(
            "src/logger.java",
            "ILogger",
            "log",
            1,
            0x00,
            vec![("ConsoleLogger".to_string(), "ILogger".to_string())],
        );
        let (k_impl, s_impl) =
            java_method("src/logger.java", "ConsoleLogger", "log", 1, 0x01, vec![]);
        gs.insert(k_iface.clone(), s_iface);
        gs.insert(k_impl.clone(), s_impl);
        gs.install_hierarchy();

        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "log",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("ILogger"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        assert_eq!(
            widened.len(),
            2,
            "expected ILogger + ConsoleLogger fan-out, got {widened:?}"
        );
        assert!(widened.contains(&k_iface));
        assert!(widened.contains(&k_impl));
    }

    /// A4, hierarchy with multiple sub-types: every implementer's
    /// matching method is in the result, deduplicated.
    #[test]
    fn widened_multiple_subtypes_returns_all() {
        let mut gs = GlobalSummaries::new();
        // Three impls + one interface.  The interface itself has no
        // body so we omit a method on it (that is the more common
        // shape, a pure interface plus concrete classes).
        let edges = vec![
            ("FileLogger".to_string(), "ILogger".to_string()),
            ("NetLogger".to_string(), "ILogger".to_string()),
            ("StdLogger".to_string(), "ILogger".to_string()),
        ];
        let (k_file, s_file) = java_method(
            "src/file_logger.java",
            "FileLogger",
            "log",
            1,
            0x01,
            edges.clone(),
        );
        let (k_net, s_net) =
            java_method("src/net_logger.java", "NetLogger", "log", 1, 0x02, vec![]);
        let (k_std, s_std) =
            java_method("src/std_logger.java", "StdLogger", "log", 1, 0x04, vec![]);
        gs.insert(k_file.clone(), s_file);
        gs.insert(k_net.clone(), s_net);
        gs.insert(k_std.clone(), s_std);
        gs.install_hierarchy();

        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "log",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("ILogger"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        assert_eq!(widened.len(), 3, "expected three impls, got {widened:?}");
        assert!(widened.contains(&k_file));
        assert!(widened.contains(&k_net));
        assert!(widened.contains(&k_std));
    }

    /// A5, the arity filter must apply across the whole fan-out, not
    /// just the direct-receiver leg.  An implementer with a different
    /// arity must not leak into the result.
    #[test]
    fn widened_arity_filter_applies_across_fanout() {
        let mut gs = GlobalSummaries::new();
        let edges = vec![
            ("OneArg".to_string(), "IBase".to_string()),
            ("TwoArg".to_string(), "IBase".to_string()),
        ];
        let (k_one, s_one) = java_method("src/one.java", "OneArg", "do_it", 1, 0x01, edges.clone());
        let (k_two, s_two) = java_method("src/two.java", "TwoArg", "do_it", 2, 0x02, vec![]);
        gs.insert(k_one.clone(), s_one);
        gs.insert(k_two.clone(), s_two);
        gs.install_hierarchy();

        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "do_it",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("IBase"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        assert_eq!(widened, vec![k_one], "arity-2 impl must be filtered out");
    }

    /// A6, fan-out is bounded at `MAX_HIERARCHY_FANOUT`.  Build a
    /// hierarchy with more impls than the cap allows and assert the
    /// result is exactly capped (and that early impls are preserved
    ///, the cap drops the *tail*, not the head).
    #[test]
    fn widened_caps_at_max_hierarchy_fanout() {
        let cap = GlobalSummaries::MAX_HIERARCHY_FANOUT;
        let mut gs = GlobalSummaries::new();

        // Build cap+3 impls so we can assert the tail truncates and a
        // deterministic prefix remains.
        let extra = 3;
        let total = cap + extra;
        let edges: Vec<(String, String)> = (0..total)
            .map(|i| (format!("Impl{i:02}"), "IBase".to_string()))
            .collect();

        // Carrier, first impl carries every edge so the index is
        // populated in one shot.
        let (k0, s0) = java_method("src/impl00.java", "Impl00", "run", 0, 0x01, edges);
        gs.insert(k0.clone(), s0);
        for i in 1..total {
            let (k, s) = java_method(
                &format!("src/impl{i:02}.java"),
                &format!("Impl{i:02}"),
                "run",
                0,
                0x01,
                vec![],
            );
            gs.insert(k, s);
        }
        gs.install_hierarchy();

        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "run",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("IBase"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(0),
        });
        assert_eq!(
            widened.len(),
            cap,
            "fan-out must cap at MAX_HIERARCHY_FANOUT={cap}, got {}",
            widened.len()
        );
    }

    /// A7, when hierarchy widening produces no candidates AND the
    /// receiver_type lookup is authoritative (Step 1), the secondary
    /// fall-through goes through `resolve_callee` which returns
    /// Ambiguous/NotFound rather than silently picking an unrelated
    /// leaf, exactly the "subset of today's targets, never a
    /// superset" rule.  Test asserts the empty result is preserved.
    #[test]
    fn widened_empty_does_not_silently_pick_unrelated_leaf() {
        let mut gs = GlobalSummaries::new();
        // Edge: IUnused has a sub Used, but neither declares
        // `something`.  An unrelated free function `something` exists
        // in the same namespace, under today's authoritative
        // receiver_type rules, that function MUST NOT be picked when
        // the call is annotated with receiver_type "IUnused".
        let edges = vec![("Used".to_string(), "IUnused".to_string())];
        let (k_carrier, s_carrier) =
            java_method("src/util.java", "Used", "carrier", 0, 0x00, edges);
        let (k_free, s_free) = free_summary("src/app.java", "something", 0, 0x01);
        gs.insert(k_carrier, s_carrier);
        gs.insert(k_free, s_free);
        gs.install_hierarchy();

        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "something",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("IUnused"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(0),
        });
        assert!(
            widened.is_empty(),
            "receiver_type IUnused with no matching method must NOT silently \
             pick an unrelated free function — got {widened:?}"
        );
    }

    /// A7b, when hierarchy widening produces nothing AND today's
    /// `resolve_callee` *does* resolve (no receiver_type, just bare
    /// leaf or qualifier hint), the fallback returns the single key.
    /// This pins the secondary-fallback contract on the path where it
    /// actually matters (no authoritative receiver_type).
    #[test]
    fn widened_falls_through_when_resolve_callee_resolves() {
        let mut gs = GlobalSummaries::new();
        let (k_free, s_free) = free_summary("src/app.java", "helper", 0, 0x01);
        gs.insert(k_free.clone(), s_free);
        gs.install_hierarchy();

        // No receiver_type → first branch of `resolve_callee_widened`
        // is the single-result fallback path.
        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "helper",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(0),
        });
        assert_eq!(widened, vec![k_free]);
    }

    /// A8, receiver_type is None → no widening; behaves identically
    /// to `resolve_callee` (single-result wrap).
    #[test]
    fn widened_no_receiver_type_collapses_to_resolve_callee() {
        let mut gs = GlobalSummaries::new();
        let (k_free, s_free) = free_summary("src/app.java", "helper", 0, 0x01);
        gs.insert(k_free.clone(), s_free);
        gs.install_hierarchy();

        let widened = gs.resolve_callee_widened(&CalleeQuery {
            name: "helper",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(0),
        });
        assert_eq!(widened, vec![k_free]);
    }

    /// A9, `merge()` must invalidate the cached hierarchy index so a
    /// post-merge call to `resolve_callee_widened` doesn't look up a
    /// stale view.  Since `install_hierarchy` is required after merges,
    /// the test asserts: post-merge, before reinstall, fan-out must
    /// fall through to single-result behaviour.
    #[test]
    fn merge_invalidates_hierarchy_cache() {
        let mut gs_a = GlobalSummaries::new();
        let edges = vec![("Sub".to_string(), "Super".to_string())];
        let (k_super, s_super) = java_method("src/super.java", "Super", "m", 0, 0x00, edges);
        let (k_sub, s_sub) = java_method("src/sub.java", "Sub", "m", 0, 0x01, vec![]);
        gs_a.insert(k_super.clone(), s_super);
        gs_a.insert(k_sub.clone(), s_sub);
        gs_a.install_hierarchy();
        // Before merge: fan-out works.
        let pre_merge = gs_a.resolve_callee_widened(&CalleeQuery {
            name: "m",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("Super"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(0),
        });
        assert_eq!(pre_merge.len(), 2);

        // Merge in an empty `gs_b`, should invalidate the cached
        // hierarchy.
        gs_a.merge(GlobalSummaries::new());
        assert!(
            gs_a.hierarchy().is_none(),
            "merge() must clear the cached hierarchy"
        );

        // After merge, before reinstall: the resolver must fall back
        // to single-result behaviour (no fan-out).
        let post_merge_no_install = gs_a.resolve_callee_widened(&CalleeQuery {
            name: "m",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("Super"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(0),
        });
        assert_eq!(post_merge_no_install.len(), 1);
        assert_eq!(post_merge_no_install[0], k_super);

        // After reinstall: fan-out is restored.
        gs_a.install_hierarchy();
        let post_merge_reinstalled = gs_a.resolve_callee_widened(&CalleeQuery {
            name: "m",
            caller_lang: Lang::Java,
            caller_namespace: "src/app.java",
            caller_container: None,
            receiver_type: Some("Super"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(0),
        });
        assert_eq!(post_merge_reinstalled.len(), 2);
        assert!(post_merge_reinstalled.contains(&k_super));
        assert!(post_merge_reinstalled.contains(&k_sub));
    }
}

#[test]
fn cross_package_imports_round_trip_via_global_summaries() {
    use crate::symbol::{FuncKey, FuncKind, Lang};
    let mut gs = GlobalSummaries::new();
    let mut map: std::collections::HashMap<String, FuncKey> = std::collections::HashMap::new();
    map.insert(
        "escape".to_string(),
        FuncKey::from_parts(
            Lang::TypeScript,
            "packages/util/src/escape.ts".to_string(),
            String::new(),
            "escape".to_string(),
            None,
            None,
            FuncKind::Function,
        ),
    );
    let arc = std::sync::Arc::new(map);
    gs.insert_cross_package_imports("apps/api/handler.ts".to_string(), arc.clone());

    assert_eq!(gs.cross_package_imports_len(), 1);
    let looked_up = gs
        .get_cross_package_imports("apps/api/handler.ts")
        .expect("namespace lookup must hit");
    assert_eq!(looked_up.len(), 1);
    assert!(looked_up.contains_key("escape"));
    assert!(gs.get_cross_package_imports("missing").is_none());

    // Inserting an empty map is a no-op so the index does not get
    // polluted with bookkeeping rows when a file's resolver produces
    // no resolved bindings.
    gs.insert_cross_package_imports(
        "apps/api/no_imports.ts".to_string(),
        std::sync::Arc::new(std::collections::HashMap::new()),
    );
    assert_eq!(gs.cross_package_imports_len(), 1);
}

#[test]
fn cross_package_imports_merged_across_thread_local_summaries() {
    use crate::symbol::{FuncKey, FuncKind, Lang};

    let mut gs_a = GlobalSummaries::new();
    let mut map_a: std::collections::HashMap<String, FuncKey> = std::collections::HashMap::new();
    map_a.insert(
        "escape".to_string(),
        FuncKey::from_parts(
            Lang::TypeScript,
            "packages/util/src/escape.ts".to_string(),
            String::new(),
            "escape".to_string(),
            None,
            None,
            FuncKind::Function,
        ),
    );
    gs_a.insert_cross_package_imports(
        "apps/api/handler_a.ts".to_string(),
        std::sync::Arc::new(map_a),
    );

    let mut gs_b = GlobalSummaries::new();
    let mut map_b: std::collections::HashMap<String, FuncKey> = std::collections::HashMap::new();
    map_b.insert(
        "format".to_string(),
        FuncKey::from_parts(
            Lang::TypeScript,
            "packages/util/src/format.ts".to_string(),
            String::new(),
            "format".to_string(),
            None,
            None,
            FuncKind::Function,
        ),
    );
    gs_b.insert_cross_package_imports(
        "apps/api/handler_b.ts".to_string(),
        std::sync::Arc::new(map_b),
    );

    gs_a.merge(gs_b);
    assert_eq!(gs_a.cross_package_imports_len(), 2);
    assert!(
        gs_a.get_cross_package_imports("apps/api/handler_a.ts")
            .is_some()
    );
    assert!(
        gs_a.get_cross_package_imports("apps/api/handler_b.ts")
            .is_some()
    );
}

// ── SCC change tracking and canonical sink sets ─────────────────────────

/// The change log must report exactly the keys a whole-map snapshot diff
/// reports: a changed key, a key that did not exist before, and nothing
/// for a rewrite with an identical value.
#[test]
fn summary_change_log_matches_snapshot_diff() {
    let mut gs = GlobalSummaries::new();
    let (k_same, s_same) = free_summary("src/a.java", "same", 1, 0x01);
    let (k_grow, s_grow) = free_summary("src/a.java", "grow", 1, 0x01);
    let (k_untouched, s_untouched) = free_summary("src/b.java", "untouched", 1, 0x01);
    gs.insert(k_same.clone(), s_same.clone());
    gs.insert(k_grow.clone(), s_grow.clone());
    gs.insert(k_untouched.clone(), s_untouched);
    gs.insert_ssa(k_same.clone(), SsaFuncSummary::default());
    gs.insert_ssa(k_grow.clone(), SsaFuncSummary::default());

    let caps_before = gs.snapshot_caps();
    let ssa_before = gs.snapshot_ssa().clone();

    let mut log = SummaryChangeLog::new();
    gs.insert_tracked(k_same.clone(), s_same, &mut log);
    gs.insert_ssa_tracked(k_same.clone(), SsaFuncSummary::default(), &mut log);
    let grown = FuncSummary {
        sink_caps: 0x03,
        ..s_grow
    };
    gs.insert_tracked(k_grow.clone(), grown, &mut log);
    let grown_ssa = SsaFuncSummary {
        source_caps: Cap::ENV_VAR,
        ..Default::default()
    };
    gs.insert_ssa_tracked(k_grow.clone(), grown_ssa, &mut log);
    let (k_new, s_new) = free_summary("src/a.java", "fresh", 1, 0x01);
    gs.insert_tracked(k_new.clone(), s_new, &mut log);
    gs.insert_ssa_tracked(k_new.clone(), SsaFuncSummary::default(), &mut log);

    let caps_after = gs.snapshot_caps();
    let mut want_caps: Vec<FuncKey> = caps_after
        .iter()
        .filter(|(k, v)| caps_before.get(*k) != Some(*v))
        .map(|(k, _)| k.clone())
        .collect();
    let mut want_ssa: Vec<FuncKey> = gs
        .snapshot_ssa()
        .iter()
        .filter(|(k, v)| ssa_before.get(*k) != Some(*v))
        .map(|(k, _)| k.clone())
        .collect();
    let mut got_caps: Vec<FuncKey> = log.changed_cap_keys(&gs).into_iter().collect();
    let mut got_ssa: Vec<FuncKey> = log.changed_ssa_keys(&gs).into_iter().collect();
    for v in [&mut want_caps, &mut want_ssa, &mut got_caps, &mut got_ssa] {
        v.sort_by_key(|k| k.to_string());
    }
    assert_eq!(got_caps, want_caps);
    assert_eq!(got_ssa, want_ssa);
    assert_eq!(got_caps.len(), 2, "grow and fresh changed caps");
    assert_eq!(got_ssa.len(), 2, "grow and fresh changed SSA");
    assert!(!got_caps.contains(&k_same) && !got_ssa.contains(&k_same));
    assert!(!got_caps.contains(&k_untouched));
    assert_eq!(
        log.ssa_before(&k_grow),
        Some(&SsaFuncSummary::default()),
        "the log keeps the value from before the first write"
    );

    // Rewriting a summary with the same facts in a different order is not
    // a change.
    let site = |line| SinkSite {
        file_rel: "a.java".into(),
        line,
        col: 1,
        snippet: String::new(),
        cap: Cap::SQL_QUERY,
        from_chain: true,
    };
    let ordered = SsaFuncSummary {
        param_to_sink: vec![(0, smallvec![site(3), site(9)])],
        ..Default::default()
    };
    let flipped = SsaFuncSummary {
        param_to_sink: vec![(0, smallvec![site(9), site(3)])],
        ..Default::default()
    };
    let (k_order, _) = free_summary("src/c.java", "reorder", 1, 0x01);
    gs.insert_ssa(k_order.clone(), ordered);
    let mut log = SummaryChangeLog::new();
    gs.insert_ssa_tracked(k_order, flipped, &mut log);
    assert!(log.changed_ssa_keys(&gs).is_empty());
}

fn site(line: u32, cap: Cap, from_chain: bool) -> SinkSite {
    SinkSite {
        file_rel: "main.go".into(),
        line,
        col: 2,
        snippet: format!("line {line}"),
        cap,
        from_chain,
    }
}

/// Two summaries holding the same sink facts in a different order must
/// compare equal after canonicalisation, and `same_facts` must say so
/// without canonicalising either.  The SCC fixed-point loop compares
/// summaries this way; an order that flips on every iteration otherwise
/// keeps a recursive batch running to its cap.
#[test]
fn canonicalize_makes_sink_set_order_irrelevant() {
    let a = SsaFuncSummary {
        param_to_sink: vec![
            (1, smallvec![site(9, Cap::SQL_QUERY, false)]),
            (
                0,
                smallvec![
                    site(34, Cap::HEADER_INJECTION, true),
                    site(53, Cap::HEADER_INJECTION, true)
                ],
            ),
        ],
        param_to_sink_param: vec![
            (0, 2, Cap::HEADER_INJECTION),
            (0, 0, Cap::HEADER_INJECTION),
            (0, 0, Cap::HEADER_INJECTION),
        ],
        param_to_gate_filters: vec![(1, Cap::SSRF), (0, Cap::SSRF), (1, Cap::SSRF)],
        validated_params_to_return: smallvec![2, 0, 2],
        ..Default::default()
    };
    let b = SsaFuncSummary {
        param_to_sink: vec![
            (0, smallvec![site(53, Cap::HEADER_INJECTION, true)]),
            (1, smallvec![site(9, Cap::SQL_QUERY, false)]),
            // A second entry for the same parameter, as a merge of two
            // extraction passes can produce.  The duplicate site upgrades
            // to `from_chain` like `union_sink_sites` does.
            (
                0,
                smallvec![
                    site(34, Cap::HEADER_INJECTION, false),
                    site(34, Cap::HEADER_INJECTION, true)
                ],
            ),
        ],
        param_to_sink_param: vec![(0, 0, Cap::HEADER_INJECTION), (0, 2, Cap::HEADER_INJECTION)],
        param_to_gate_filters: vec![(0, Cap::SSRF), (1, Cap::SSRF)],
        validated_params_to_return: smallvec![0, 2],
        ..Default::default()
    };
    assert_ne!(a, b);
    assert!(a.same_facts(&b) && b.same_facts(&a));
    let mut fewer = b.clone();
    fewer.param_to_sink.pop();
    assert!(!a.same_facts(&fewer), "a dropped site is a different fact");
    let (mut a, mut b) = (a, b);
    a.canonicalize();
    b.canonicalize();
    assert_eq!(a, b);
    assert_eq!(
        a.param_to_sink
            .iter()
            .map(|(i, s)| (*i, s.iter().map(|s| s.line).collect::<Vec<_>>()))
            .collect::<Vec<_>>(),
        vec![(0, vec![34, 53]), (1, vec![9])]
    );
    assert!(a.param_to_sink[0].1.iter().all(|s| s.from_chain));
    assert_eq!(
        a.param_to_sink_param,
        vec![(0, 0, Cap::HEADER_INJECTION), (0, 2, Cap::HEADER_INJECTION)]
    );
    assert_eq!(
        a.param_to_gate_filters,
        vec![(0, Cap::SSRF), (1, Cap::SSRF)]
    );
    assert_eq!(a.validated_params_to_return.as_slice(), &[0, 2]);

    // Idempotent.
    let once = a.clone();
    a.canonicalize();
    assert_eq!(a, once);
}

// ── Receiver-aware caller-container resolution ──────────────────────────

#[test]
fn classify_call_receiver_shapes() {
    use crate::summary::{CallReceiver, classify_call_receiver};
    let own = |lang, r: Option<&str>| classify_call_receiver(lang, r, Some("Person"));
    assert_eq!(own(Lang::Java, None), CallReceiver::Own);
    for r in ["this", "self", "$this", "static", "Self", "cls", "Person"] {
        assert_eq!(own(Lang::Java, Some(r)), CallReceiver::Own, "{r}");
    }
    for r in ["super", "super()", "super(Sub, self)", "parent"] {
        assert_eq!(own(Lang::Java, Some(r)), CallReceiver::Super, "{r}");
    }
    for r in ["repo", "name", "sb", "$this->inner", "@repo", "json"] {
        assert_eq!(own(Lang::Java, Some(r)), CallReceiver::Other, "{r}");
    }
    // Go names its method receiver freely, so a plain identifier may be
    // the caller's own receiver.
    assert_eq!(own(Lang::Go, Some("h")), CallReceiver::Own);
}

fn query_with<'a>(
    name: &'a str,
    caller_namespace: &'a str,
    caller_container: Option<&'a str>,
    receiver_var: Option<&'a str>,
    arity: usize,
) -> CalleeQuery<'a> {
    CalleeQuery {
        name,
        caller_lang: Lang::Java,
        caller_namespace,
        caller_container,
        receiver_type: None,
        namespace_qualifier: None,
        receiver_var,
        arity: Some(arity),
    }
}

/// `repo.find(id)` inside `Person.find` names another object's `find`, so
/// the caller-container step must not bind it to `Person.find`; `this.find`
/// and a bare `find` still resolve to the caller's own method.
#[test]
fn caller_container_step_only_for_own_receiver() {
    let mut gs = GlobalSummaries::new();
    let (k_person, s_person) = method_summary("src/Person.java", "Person", "find", 1, 0x01);
    let (k_repo, s_repo) = method_summary("src/Person.java", "Repo", "find", 1, 0x02);
    let (k_cache, s_cache) = method_summary("src/Cache.java", "Cache", "find", 1, 0x04);
    gs.insert(k_person.clone(), s_person);
    gs.insert(k_repo, s_repo);
    gs.insert(k_cache, s_cache);

    let ns = "src/Person.java";
    for rv in [None, Some("this")] {
        assert_eq!(
            gs.resolve_callee(&query_with("find", ns, Some("Person"), rv, 1)),
            CalleeResolution::Resolved(k_person.clone()),
            "receiver {rv:?}"
        );
    }
    assert!(matches!(
        gs.resolve_callee(&query_with("find", ns, Some("Person"), Some("repo"), 1)),
        CalleeResolution::Ambiguous(_)
    ));
}

/// `super.init(cfg)` inside `Sub.init` resolves to the closest supertype
/// that defines `init`, never to `Sub.init` itself, and is unresolved
/// when no supertype is known.
#[test]
fn super_call_resolves_through_type_hierarchy() {
    let mut gs = GlobalSummaries::new();
    let (k_sub, mut s_sub) = method_summary("src/Sub.java", "Sub", "init", 1, 0x01);
    s_sub.hierarchy_edges = vec![("Sub".into(), "Mid".into())];
    let (k_mid, mut s_mid) = method_summary("src/Mid.java", "Mid", "other", 0, 0x00);
    s_mid.hierarchy_edges = vec![("Mid".into(), "Base".into())];
    let (k_base, s_base) = method_summary("src/Base.java", "Base", "init", 1, 0x02);
    gs.insert(k_sub.clone(), s_sub);
    gs.insert(k_mid, s_mid);
    gs.insert(k_base.clone(), s_base);

    let q = query_with("init", "src/Sub.java", Some("Sub"), Some("super"), 1);
    assert_eq!(
        gs.resolve_callee(&q),
        CalleeResolution::NotFound,
        "without an installed hierarchy a super call has no target"
    );
    gs.install_hierarchy();
    assert_eq!(gs.supertypes_of(Lang::Java, "Sub"), vec!["Mid", "Base"]);
    assert_eq!(gs.resolve_callee(&q), CalleeResolution::Resolved(k_base));
    let parent = query_with("init", "src/Sub.java", Some("Sub"), Some("parent"), 1);
    assert_ne!(
        gs.resolve_callee(&parent),
        CalleeResolution::Resolved(k_sub)
    );
}

// ── Resolver oracle ─────────────────────────────────────────────────────
//
// `resolve_callee` counts candidate sets in place and clones keys only for
// the answer it returns. The version below is the resolver as it was before
// that change (it builds a Vec per step and clones the ambiguous list). Both
// have to agree on every query, including the order of an ambiguous list.
mod resolve_callee_oracle_tests {
    use super::*;

    /// The pre-refactor resolver, kept verbatim as an oracle.
    #[allow(clippy::needless_borrow)]
    fn reference_resolve_callee(gs: &GlobalSummaries, q: &CalleeQuery<'_>) -> CalleeResolution {
        // ── Helpers ─────────────────────────────────────────────────
        let arity_matches = |k: &FuncKey| match q.arity {
            Some(a) => k.arity == Some(a),
            None => true,
        };

        // Look up `{container}::{name}` and return a single arity-matched
        // candidate if one exists (using same-namespace to break ties).
        let try_qualified = |container: &str| -> Option<FuncKey> {
            if container.is_empty() {
                return None;
            }
            let qual = format!("{container}::{}", q.name);
            let candidates: Vec<&FuncKey> = gs
                .lookup_qualified(q.caller_lang, &qual)
                .into_iter()
                .map(|(k, _)| k)
                .filter(|k| arity_matches(k))
                .collect();
            match candidates.len() {
                0 => None,
                1 => Some(candidates[0].clone()),
                _ => {
                    let same_ns: Vec<&FuncKey> = candidates
                        .iter()
                        .copied()
                        .filter(|k| k.namespace == q.caller_namespace)
                        .collect();
                    if same_ns.len() == 1 {
                        Some(same_ns[0].clone())
                    } else {
                        None
                    }
                }
            }
        };

        // ── Step 1: receiver_type (authoritative) ───────────────────
        if let Some(rt) = q.receiver_type {
            if let Some(key) = try_qualified(rt) {
                return CalleeResolution::Resolved(key);
            }
            // Authoritative miss: before returning, check whether any
            // candidate exists at all for the leaf name.  If there are
            // some, report Ambiguous with the leaf candidates (so the
            // caller knows we saw the name but refused to pick the
            // wrong container).  If there are none, return NotFound.
            let bare: Vec<&FuncKey> = gs
                .lookup_same_lang(q.caller_lang, q.name)
                .into_iter()
                .map(|(k, _)| k)
                .filter(|k| arity_matches(k))
                .collect();
            return if bare.is_empty() {
                CalleeResolution::NotFound
            } else {
                CalleeResolution::Ambiguous(bare.into_iter().cloned().collect())
            };
        }

        // ── Step 2: namespace_qualifier (authoritative for `::` paths) ──
        if let Some(nq) = q.namespace_qualifier {
            if let Some(key) = try_qualified(nq) {
                return CalleeResolution::Resolved(key);
            }
            // A `::`-qualified callee names a concrete type or module.  With
            // no summary in that container it is an external associated
            // function (stdlib / third-party crate) or a module-path free
            // function — never a same-leaf METHOD in an unrelated container.
            // Refuse the caller-container (step 3) and leaf/arity fallbacks
            // (steps 4/6) that would bind the stdlib `File::open` to the
            // enclosing `impl V5Reader { fn open }`, or `BufReader::new` to a
            // unique-arity `UpdateFile::new`.  Allow only a unique same-leaf
            // FREE function (`crate::util::sanitize` → top-level `fn
            // sanitize`).  `Self::` / `self::` is a real self-call and defers
            // to the caller-container step below.
            if !matches!(nq, "Self" | "self") {
                let free: Vec<FuncKey> = gs
                    .lookup_same_lang(q.caller_lang, q.name)
                    .into_iter()
                    .map(|(k, _)| k)
                    .filter(|k| k.container.is_empty() && arity_matches(k))
                    .cloned()
                    .collect();
                return match free.len() {
                    1 => CalleeResolution::Resolved(free[0].clone()),
                    0 => CalleeResolution::NotFound,
                    _ => CalleeResolution::Ambiguous(free),
                };
            }
        }

        // ── Step 3: caller self-container ───────────────────────────
        // Only a call on the caller's own instance can land in the
        // caller's container.  `repo.find(id)` inside `find` names another
        // object's method, and `super.init(cfg)` inside `init` names the
        // supertype's, so neither may resolve to the caller.
        match q.receiver() {
            CallReceiver::Own => {
                if let Some(cc) = q.caller_container
                    && let Some(key) = try_qualified(cc)
                {
                    return CalleeResolution::Resolved(key);
                }
            }
            CallReceiver::Super => {
                // The nearest supertype that defines the method.  Like step
                // 4, tolerate a declaration with more parameters than the
                // call passes (defaults, or Python's explicit `self`).
                let in_supertype = |sup: &str| -> Option<FuncKey> {
                    try_qualified(sup).or_else(|| {
                        let a = q.arity?;
                        let qual = format!("{sup}::{}", q.name);
                        let wider: Vec<&FuncKey> = gs
                            .lookup_qualified(q.caller_lang, &qual)
                            .into_iter()
                            .map(|(k, _)| k)
                            .filter(|k| matches!(k.arity, Some(p) if p > a))
                            .collect();
                        (wider.len() == 1).then(|| wider[0].clone())
                    })
                };
                return match q.caller_container {
                    Some(cc) => gs
                        .supertypes_of(q.caller_lang, cc)
                        .iter()
                        .find_map(|sup| in_supertype(sup))
                        .map_or(CalleeResolution::NotFound, CalleeResolution::Resolved),
                    None => CalleeResolution::NotFound,
                };
            }
            CallReceiver::Other => {}
        }

        // ── Step 4: same-namespace unique leaf ──────────────────────
        let all_candidates: Vec<&FuncKey> = gs
            .lookup_same_lang(q.caller_lang, q.name)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        if all_candidates.is_empty() {
            return CalleeResolution::NotFound;
        }

        let mut arity_filtered: Vec<&FuncKey> = all_candidates
            .iter()
            .copied()
            .filter(|k| arity_matches(k))
            .collect();
        if arity_filtered.is_empty() {
            // Exact-arity match found nothing. Tolerate under-application:
            // `FuncKey::arity` is the *total* parameter count, so a call
            // supplying `a` arguments to a function declared with more
            // parameters (the surplus being default-valued / optional) is a
            // routine, valid call shape in Python, JS/TS, PHP, and Ruby. Retry
            // with `param_count >= call_arity` so these calls still resolve.
            //
            // This only ever WIDENS the candidate set, and resolution below
            // still requires a unique candidate, so a genuinely ambiguous name
            // degrades to `Ambiguous`, never a wrong `Resolved`. Exact-arity
            // matches always take precedence (this branch runs only when none
            // exist), so no existing exact-match resolution regresses.
            if let Some(a) = q.arity.filter(|_| q.caller_lang.allows_under_application()) {
                arity_filtered = all_candidates
                    .iter()
                    .copied()
                    .filter(|k| matches!(k.arity, Some(p) if p >= a))
                    .collect();
            }
            if arity_filtered.is_empty() {
                return CalleeResolution::NotFound;
            }
        }

        let same_ns: Vec<&FuncKey> = arity_filtered
            .iter()
            .copied()
            .filter(|k| k.namespace == q.caller_namespace)
            .collect();
        if same_ns.len() == 1 {
            return CalleeResolution::Resolved(same_ns[0].clone());
        }

        // ── Step 5: receiver_var tie-break (soft) ───────────────────
        if let Some(rv) = q.receiver_var
            && let Some(key) = try_qualified(rv)
        {
            return CalleeResolution::Resolved(key);
        }

        // ── Step 5.5: bare-call free-function preference ────────────
        // A call with no receiver, no namespace qualifier, and no
        // authoritative receiver type is syntactically a free-function
        // invocation: a class method cannot be invoked that way from
        // outside its own class (intra-class self-calls were already
        // resolved by step 3).  When the same-namespace candidate set
        // contains exactly one empty-container entry, it is the
        // unambiguous target, returning Ambiguous here would be a
        // silent false negative whenever a top-level helper happens to
        // share a name with some method elsewhere in the file.
        let syntactic_bare = q.receiver_type.is_none()
            && q.namespace_qualifier.is_none()
            && q.receiver_var.is_none();
        if syntactic_bare {
            let empty_container_same_ns: Vec<&FuncKey> = same_ns
                .iter()
                .copied()
                .filter(|k| k.container.is_empty())
                .collect();
            if empty_container_same_ns.len() == 1 {
                return CalleeResolution::Resolved(empty_container_same_ns[0].clone());
            }
        }

        // ── Step 6: leaf fallback ───────────────────────────────────
        if arity_filtered.len() == 1 {
            return CalleeResolution::Resolved(arity_filtered[0].clone());
        }

        // Multiple arity-matched candidates remain.  When a qualified
        // hint was supplied but missed, refuse to guess, a silent
        // leaf-name pick would defeat the point of qualified-first
        // resolution.  (`receiver_type` is handled in Step 1 and never
        // reaches here; `namespace_qualifier` / `caller_container`
        // missing their target flow through as a soft miss.)
        if q.has_qualified_hint() {
            return CalleeResolution::Ambiguous(arity_filtered.into_iter().cloned().collect());
        }

        // No qualified hints whatsoever, tolerate namespace narrowing.
        match same_ns.len() {
            1 => CalleeResolution::Resolved(same_ns[0].clone()),
            0 => CalleeResolution::Ambiguous(arity_filtered.into_iter().cloned().collect()),
            _ => CalleeResolution::Ambiguous(same_ns.into_iter().cloned().collect()),
        }
    }

    fn populated() -> GlobalSummaries {
        let mut gs = GlobalSummaries::new();
        let langs = [Lang::Java, Lang::Python];
        let namespaces = ["a.java", "b.java", "c.java"];
        let containers = ["", "A", "B"];
        let names = ["get", "run", "id"];
        let mut n = 0u32;
        for lang in langs {
            for ns in namespaces {
                for container in containers {
                    for name in names {
                        for arity in 0..3usize {
                            n += 1;
                            // Leave gaps so some names are unique in a namespace,
                            // some ambiguous and some missing.
                            if (n * 7 + arity as u32).is_multiple_of(3) {
                                continue;
                            }
                            let kind = if container.is_empty() {
                                FuncKind::Function
                            } else {
                                FuncKind::Method
                            };
                            let key = FuncKey::from_parts(
                                lang,
                                ns,
                                container,
                                name,
                                Some(arity),
                                Some(n),
                                kind,
                            );
                            let mut summary = FuncSummary {
                                name: name.into(),
                                file_path: ns.into(),
                                lang: lang.as_str().into(),
                                param_count: arity,
                                container: container.into(),
                                disambig: Some(n),
                                kind,
                                ..Default::default()
                            };
                            if container == "A" {
                                summary.hierarchy_edges = vec![("A".into(), "B".into())];
                            }
                            gs.insert(key, summary);
                        }
                    }
                }
            }
        }
        gs.install_hierarchy();
        gs
    }

    #[test]
    fn resolve_callee_matches_the_reference_on_every_query_shape() {
        let gs = populated();
        let (mut resolved, mut ambiguous, mut not_found) = (0usize, 0usize, 0usize);
        for lang in [Lang::Java, Lang::Python] {
            for name in ["get", "run", "id", "missing"] {
                for caller_namespace in ["a.java", "c.java", "elsewhere.java"] {
                    for caller_container in [None, Some("A"), Some("B"), Some("Z")] {
                        for receiver_type in [None, Some("A"), Some("B"), Some("Z")] {
                            for namespace_qualifier in [None, Some("A"), Some("Self"), Some("util")]
                            {
                                for receiver_var in
                                    [None, Some("this"), Some("super"), Some("A"), Some("other")]
                                {
                                    for arity in [None, Some(0), Some(1), Some(3)] {
                                        let q = CalleeQuery {
                                            name,
                                            caller_lang: lang,
                                            caller_namespace,
                                            caller_container,
                                            receiver_type,
                                            namespace_qualifier,
                                            receiver_var,
                                            arity,
                                        };
                                        let got = gs.resolve_callee(&q);
                                        let want = reference_resolve_callee(&gs, &q);
                                        assert_eq!(got, want, "{q:?}");
                                        let unique = gs.resolve_callee_unique(&q);
                                        match &want {
                                            CalleeResolution::Resolved(k) => {
                                                resolved += 1;
                                                assert_eq!(unique.as_ref(), Some(k), "{q:?}");
                                            }
                                            CalleeResolution::Ambiguous(_) => {
                                                ambiguous += 1;
                                                assert_eq!(unique, None, "{q:?}");
                                            }
                                            CalleeResolution::NotFound => {
                                                not_found += 1;
                                                assert_eq!(unique, None, "{q:?}");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // The grid must exercise every outcome, or the comparison proves little.
        assert!(
            resolved > 500 && ambiguous > 500 && not_found > 500,
            "resolved={resolved} ambiguous={ambiguous} not_found={not_found}"
        );
    }

    /// A name shared by many functions answers `resolve_callee_unique` without
    /// the candidate list, and keeps the same answer as `resolve_callee`.
    #[test]
    fn unique_resolution_of_a_widely_shared_name() {
        let mut gs = GlobalSummaries::new();
        for i in 0..300 {
            let (k, s) = method_summary(
                &format!("src/M{i}.java"),
                &format!("Model{i}"),
                "getId",
                0,
                0,
            );
            gs.insert(k, s);
        }
        let (k_free, s_free) = free_summary("src/Caller.java", "getId", 0, 0);
        gs.insert(k_free.clone(), s_free);
        let q = CalleeQuery {
            name: "getId",
            caller_lang: Lang::Java,
            caller_namespace: "src/Caller.java",
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(0),
        };
        // Bare call, one free function in the caller's namespace: it wins.
        assert_eq!(gs.resolve_callee_unique(&q), Some(k_free));
        // A call on some object cannot pick among 301 candidates.
        let on_object = CalleeQuery {
            receiver_var: Some("order"),
            caller_namespace: "src/Other.java",
            ..q.clone()
        };
        assert_eq!(gs.resolve_callee_unique(&on_object), None);
        match gs.resolve_callee(&on_object) {
            CalleeResolution::Ambiguous(keys) => assert_eq!(keys.len(), 301),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn keys_same_lang_borrows_the_index_in_insertion_order() {
        let mut gs = GlobalSummaries::new();
        let (k1, s1) = method_summary("src/a.java", "A", "run", 0, 0);
        let (k2, s2) = method_summary("src/b.java", "B", "run", 0, 0);
        gs.insert(k1.clone(), s1);
        gs.insert(k2.clone(), s2);
        assert_eq!(
            gs.keys_same_lang(Lang::Java, "run"),
            &[k1.clone(), k2.clone()]
        );
        assert!(gs.keys_same_lang(Lang::Python, "run").is_empty());
        assert!(gs.keys_same_lang(Lang::Java, "walk").is_empty());
        assert_eq!(gs.keys_qualified(Lang::Java, "A::run"), &[k1]);
        // The owned view agrees with the borrowed one.
        assert_eq!(gs.lookup_same_lang(Lang::Java, "run").len(), 2);
    }
}

fn go_key(ns: &str, container: &str, name: &str) -> FuncKey {
    let kind = if container.is_empty() {
        FuncKind::Function
    } else {
        FuncKind::Method
    };
    FuncKey::from_parts(Lang::Go, ns, container, name, Some(0), None, kind)
}

#[test]
fn name_index_order_ignores_insertion_order() {
    let keys = [
        go_key("b.go", "", "run"),
        go_key("a.go", "T", "run"),
        go_key("c.go", "", "run"),
    ];
    let mut fwd = GlobalSummaries::new();
    for k in &keys {
        fwd.insert(k.clone(), make("run", 0, 0, 0));
    }
    let mut rev = GlobalSummaries::new();
    for k in keys.iter().rev() {
        rev.insert(k.clone(), make("run", 0, 0, 0));
    }
    assert_eq!(
        fwd.keys_same_lang(Lang::Go, "run"),
        rev.keys_same_lang(Lang::Go, "run")
    );
    let files: Vec<&str> = fwd
        .keys_same_lang(Lang::Go, "run")
        .iter()
        .map(|k| k.namespace.as_str())
        .collect();
    assert_eq!(files, ["a.go", "b.go", "c.go"]);
}

#[test]
fn resolution_read_depends_on_its_outcome_only() {
    let mut gs = GlobalSummaries::new();
    gs.insert(go_key("io.go", "File", "Close"), make("Close", 0, 0, 0));
    gs.insert(go_key("net.go", "Conn", "Close"), make("Close", 0, 0, 0));
    let typed = CalleeQuery {
        name: "Close",
        caller_lang: Lang::Go,
        caller_namespace: "main.go",
        caller_container: None,
        receiver_type: Some("File"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(0),
    };
    let bare = CalleeQuery {
        receiver_type: None,
        caller_namespace: "util.go",
        ..typed
    };

    let guard = deps::start_trace();
    let resolved = gs.resolve_callee_unique(&typed);
    let unresolved = gs.resolve_callee_unique(&bare);
    let trace = guard.finish();
    assert_eq!(resolved.map(|k| k.container), Some("File".to_string()));
    assert_eq!(unresolved, None, "two methods, no same-file candidate");

    let guard = deps::start_trace();
    let _ = gs.resolve_callee_unique(&typed);
    let typed_only = guard.finish();

    // A new free `Close` in util.go: `f.Close()` on a File still resolves
    // to File::Close, but a bare `Close()` inside util.go now resolves to
    // the new function.
    gs.insert(go_key("util.go", "", "Close"), make("Close", 0, 0, 0));
    assert!(
        typed_only.holds(&gs),
        "a resolution the new function does not change stays valid"
    );
    assert!(
        !trace.holds(&gs),
        "a resolution the new function changes is invalidated"
    );
}
