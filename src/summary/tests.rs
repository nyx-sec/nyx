use super::*;
use smallvec::smallvec;

/// Test helper: build a [`SmallVec`] of one cap-only [`SinkSite`] for a
/// parameter, matching the pre-`SinkSite` shape `(idx, Cap)`.  Source
/// coordinates stay default (`line=0, col=0`) since tests do not
/// exercise the primary-location attribution path at this layer.
fn cap_sites(cap: Cap) -> SmallVec<[SinkSite; 1]> {
    smallvec![SinkSite::cap_only(cap)]
}

fn make(name: &str, src: u16, san: u16, sink: u16) -> FuncSummary {
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
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "foo".into(),
        arity: Some(0),
        ..Default::default()
    };
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
    let key_a = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "helper".into(),
        arity: Some(0),
        ..Default::default()
    };
    let key_b = FuncKey {
        lang: Lang::Rust,
        namespace: "file_b.rs".into(),
        name: "helper".into(),
        arity: Some(0),
        ..Default::default()
    };
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
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "helper".into(),
        arity: Some(0),
        ..Default::default()
    };
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

    let py_key = FuncKey {
        lang: Lang::Python,
        namespace: "handler.py".into(),
        name: "process_data".into(),
        arity: Some(0),
        ..Default::default()
    };
    let c_key = FuncKey {
        lang: Lang::C,
        namespace: "handler.c".into(),
        name: "process_data".into(),
        arity: Some(1),
        ..Default::default()
    };

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
fn u16_caps_round_trip_serde() {
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

#[test]
fn backward_compat_u8_json_deserializes() {
    // Old u8-range values still deserialize correctly into u16 fields
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
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "foo".into(),
        arity: Some(0),
        ..Default::default()
    };
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
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "bar".into(),
        arity: Some(0),
        ..Default::default()
    };
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
        param_to_gate_filters: vec![],
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
        param_to_gate_filters: vec![],
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
        param_to_gate_filters: vec![],
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
        param_to_gate_filters: vec![],
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn global_summaries_insert_ssa_exact_key_replacement() {
    let mut gs = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "app.py".into(),
        name: "process".into(),
        arity: Some(1),
        ..Default::default()
    };

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
        param_to_gate_filters: vec![],
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
        param_to_gate_filters: vec![],
    };
    gs.insert_ssa(key.clone(), v2.clone());
    assert_eq!(gs.get_ssa(&key), Some(&v2));
}

#[test]
fn global_summaries_merge_with_ssa_entries() {
    let mut gs1 = GlobalSummaries::new();
    let mut gs2 = GlobalSummaries::new();

    let key_a = FuncKey {
        lang: Lang::Python,
        namespace: "a.py".into(),
        name: "foo".into(),
        arity: Some(1),
        ..Default::default()
    };
    let key_b = FuncKey {
        lang: Lang::Python,
        namespace: "b.py".into(),
        name: "bar".into(),
        arity: Some(2),
        ..Default::default()
    };

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
        param_to_gate_filters: vec![],
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
        param_to_gate_filters: vec![],
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

    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "f".into(),
        arity: Some(1),
        ..Default::default()
    };
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
            param_to_gate_filters: vec![],
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
        param_to_gate_filters: vec![],
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
        param_to_gate_filters: vec![],
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
        param_to_gate_filters: vec![],
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
fn make_callee_body(
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
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        },
        opt: crate::ssa::OptimizeResult {
            const_values: std::collections::HashMap::new(),
            type_facts: crate::ssa::type_facts::TypeFactResult {
                facts: std::collections::HashMap::new(),
            },
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
        condition: Some(Box::new(ConditionExpr::BoolTest { var: SsaValue(0) })),
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
                Some(ConditionExpr::BoolTest { var }) => {
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
    let key = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "helper.py".into(),
        name: "transform".into(),
        arity: Some(2),
        ..Default::default()
    };

    let body1 = make_callee_body(3, 2);
    let body2 = make_callee_body(5, 2);

    gs.insert_body(key.clone(), body1);
    assert_eq!(gs.get_body(&key).unwrap().ssa.blocks.len(), 3);

    // Second insert replaces (exact-key, no union)
    gs.insert_body(key.clone(), body2);
    assert_eq!(gs.get_body(&key).unwrap().ssa.blocks.len(), 5);
}

#[test]
fn global_summaries_get_body_not_found() {
    let gs = GlobalSummaries::new();
    let key = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "missing.py".into(),
        name: "nope".into(),
        arity: Some(0),
        ..Default::default()
    };
    assert!(gs.get_body(&key).is_none());
}

#[test]
fn global_summaries_merge_includes_bodies() {
    let mut gs1 = GlobalSummaries::new();
    let mut gs2 = GlobalSummaries::new();

    let key1 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "a.py".into(),
        name: "func_a".into(),
        arity: Some(1),
        ..Default::default()
    };
    let key2 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "b.py".into(),
        name: "func_b".into(),
        arity: Some(2),
        ..Default::default()
    };

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

    let key = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "util.py".into(),
        name: "helper".into(),
        arity: Some(1),
        ..Default::default()
    };

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
    let key1 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "a.py".into(),
        name: "helper".into(),
        arity: Some(1),
        ..Default::default()
    };
    let key2 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "b.py".into(),
        name: "helper".into(),
        arity: Some(1),
        ..Default::default()
    };

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

    let key1 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "a.py".into(),
        name: "helper".into(),
        arity: Some(1),
        ..Default::default()
    };
    let key2 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "b.py".into(),
        name: "helper".into(),
        arity: Some(1),
        ..Default::default()
    };

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
    let key = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "util.py".into(),
        name: "helper".into(),
        arity: Some(1),
        ..Default::default()
    };
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
            param_to_gate_filters: vec![],
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
    sink_bits: u16,
) -> (FuncKey, FuncSummary) {
    let key = FuncKey {
        lang: Lang::Java,
        namespace: namespace.into(),
        container: container.into(),
        name: name.into(),
        arity: Some(arity),
        disambig,
        kind,
    };
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
    let go_key = FuncKey {
        lang: Lang::Go,
        namespace: "lib.go".into(),
        container: String::new(),
        name: "fetch_env".into(),
        arity: Some(0),
        disambig: Some(7777),
        kind: FuncKind::Function,
    };
    let go_sum = FuncSummary {
        name: "fetch_env".into(),
        file_path: "lib.go".into(),
        lang: "go".into(),
        ..s
    };
    gs.insert(go_key, go_sum);
    let _ = k; // unused: only needed for symmetry with fs_with signature

    let interop_query = FuncKey {
        lang: Lang::Go,
        namespace: "lib.go".into(),
        container: String::new(),
        name: "fetch_env".into(),
        arity: Some(0),
        disambig: None,
        kind: FuncKind::Function,
    };
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
    let mk = |disambig: u32, bits: u16| {
        let k = FuncKey {
            lang: Lang::Go,
            namespace: "lib.go".into(),
            container: String::new(),
            name: "dup".into(),
            arity: Some(0),
            disambig: Some(disambig),
            kind: FuncKind::Function,
        };
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

    let ambiguous_query = FuncKey {
        lang: Lang::Go,
        namespace: "lib.go".into(),
        container: String::new(),
        name: "dup".into(),
        arity: Some(0),
        disambig: None,
        kind: FuncKind::Function,
    };
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
            },
            CalleeSite {
                name: "env::var".into(),
                arity: Some(1),
                receiver: None,
                qualifier: Some("env".into()),
                ordinal: 2,
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
    let caller_key = FuncKey {
        lang: Lang::Rust,
        namespace: "src/main.rs".into(),
        name: "handler".into(),
        arity: Some(0),
        ..Default::default()
    };
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
    sink_bits: u16,
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
    sink_bits: u16,
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
    let k_env = FuncKey {
        lang: Lang::Rust,
        ..k_env
    };
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
    let k_other = FuncKey {
        lang: Lang::Rust,
        ..k_other
    };
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
    sink: u16,
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
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "mod.py".into(),
        name: "run".into(),
        arity: Some(2),
        ..Default::default()
    };
    gs.insert_body(key.clone(), make_callee_body(2, 2));
    // Incoming body with a different param_count, must not overwrite.
    gs.insert_body(key.clone(), make_callee_body(5, 4));

    // Invariant 1: the original body stays at the original key (not
    // silently replaced by the param_count=4 body).
    let head = gs.get_body(&key).expect("original 2-param body kept");
    assert_eq!(head.param_count, 2);

    // Invariant 2: the conflicting body is preserved under a synthetic
    // disambig, not dropped.  Reconstruct the expected synth disambig
    // using the same formula as `reconcile_body_key`.
    let mut found_conflicting = false;
    let base = (4u32).wrapping_mul(0x9E37_79B9);
    for probe in 0u32..1024 {
        let synth = base.wrapping_add(probe);
        let synth_key = FuncKey {
            disambig: Some(0x8000_0000 | (synth & 0x7FFF_FFFF)),
            ..key.clone()
        };
        if let Some(body) = gs.get_body(&synth_key)
            && body.param_count == 4
        {
            found_conflicting = true;
            break;
        }
    }
    assert!(
        found_conflicting,
        "the 4-param body must be preserved under a synthetic disambig key"
    );
}

#[test]
fn insert_ssa_arity_overflow_rekeys() {
    // Key claims arity 1, but the incoming SSA summary references
    // param index 3, structurally impossible for the same function.
    // The fix must split so the key arity invariant is preserved.
    let mut gs = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "mod.py".into(),
        name: "f".into(),
        arity: Some(1),
        ..Default::default()
    };

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
    let key = FuncKey {
        lang: Lang::Java,
        namespace: "Reader.java".into(),
        container: "Reader".into(),
        name: "read".into(),
        arity: Some(0),
        ..Default::default()
    };
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
    let key = FuncKey {
        lang: Lang::Java,
        namespace: "Reader.java".into(),
        container: "Reader".into(),
        name: "read".into(),
        arity: Some(0),
        ..Default::default()
    };
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
    };
    let site_b = SinkSite {
        file_rel: "exec.py".into(),
        line: 33,
        col: 12,
        snippet: "subprocess.call(cmd, shell=True)".into(),
        cap: Cap::CODE_EXEC | Cap::SHELL_ESCAPE,
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
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "svc.py".into(),
        name: "run".into(),
        arity: Some(1),
        ..Default::default()
    };

    let site_a = SinkSite {
        file_rel: "svc.py".into(),
        line: 10,
        col: 1,
        snippet: "execute(sql)".into(),
        cap: Cap::SQL_QUERY,
    };
    let site_b = SinkSite {
        file_rel: "svc.py".into(),
        line: 20,
        col: 4,
        snippet: "os.system(cmd)".into(),
        cap: Cap::CODE_EXEC,
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
        param_to_gate_filters: vec![],
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
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "helper".into(),
        arity: Some(2), // too small for idx 5, synthetic-Param marker
        ..Default::default()
    };
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
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "helper".into(),
        arity: Some(2),
        ..Default::default()
    };
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

    fn method_summary(name: &str, container: &str, file: &str, sink_caps: u16) -> FuncSummary {
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
    let repo_key = FuncKey {
        lang: Lang::Rust,
        namespace: "src/repo.rs".into(),
        container: "Repository".into(),
        name: "findById".into(),
        arity: Some(1),
        ..Default::default()
    };
    let cache_key = FuncKey {
        lang: Lang::Rust,
        namespace: "src/cache.rs".into(),
        container: "UnsafeCache".into(),
        name: "findById".into(),
        arity: Some(1),
        ..Default::default()
    };

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
        sink_bits: u16,
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
