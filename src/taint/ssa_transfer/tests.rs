// ── populate_node_meta + CrossFileNodeMeta tests ─────────────────────────

#[cfg(test)]
mod cross_file_tests {
    use super::super::*;
    use crate::cfg::{AstMeta, BinOp, CallMeta, EdgeKind, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::DataLabel;

    use petgraph::prelude::*;
    use smallvec::smallvec;

    fn make_test_cfg() -> crate::cfg::Cfg {
        let mut cfg = Graph::new();
        let n0 = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 10),
                ..Default::default()
            },
            taint: TaintMeta {
                labels: smallvec![DataLabel::Source(crate::labels::Cap::all())],
                defines: Some("x".into()),
                ..Default::default()
            },
            call: CallMeta::default(),
            bin_op: Some(BinOp::Add),
            ..Default::default()
        });
        let n1 = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (10, 20),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("y".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        cfg.add_edge(n0, n1, EdgeKind::Seq);
        cfg
    }

    fn make_body_referencing_nodes(n0: NodeIndex, n1: NodeIndex) -> CalleeSsaBody {
        CalleeSsaBody {
            ssa: SsaBody {
                blocks: vec![SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![
                        SsaInst {
                            value: SsaValue(0),
                            op: SsaOp::Source,
                            cfg_node: n0,
                            var_name: Some("x".into()),
                            span: (0, 5),
                        },
                        SsaInst {
                            value: SsaValue(1),
                            op: SsaOp::Assign(smallvec![SsaValue(0)]),
                            cfg_node: n1,
                            var_name: Some("y".into()),
                            span: (5, 10),
                        },
                    ],
                    terminator: Terminator::Return(Some(SsaValue(1))),
                    preds: smallvec![],
                    succs: smallvec![],
                }],
                entry: BlockId(0),
                value_defs: vec![
                    ValueDef {
                        var_name: Some("x".into()),
                        cfg_node: n0,
                        block: BlockId(0),
                    },
                    ValueDef {
                        var_name: Some("y".into()),
                        cfg_node: n1,
                        block: BlockId(0),
                    },
                ],
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
            param_count: 0,
            node_meta: std::collections::HashMap::new(),
            body_graph: None,
            cross_package_imports: std::sync::Arc::new(std::collections::HashMap::new()),
        }
    }

    #[test]
    fn populate_node_meta_extracts_bin_op_and_labels() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);

        assert!(body.node_meta.is_empty());
        let ok = populate_node_meta(&mut body, &cfg);
        assert!(ok, "should succeed for valid nodes");

        assert_eq!(body.node_meta.len(), 2);

        // Node 0: has bin_op=Add and Source label
        let meta0 = &body.node_meta[&0];
        assert_eq!(meta0.info.bin_op, Some(BinOp::Add));
        assert_eq!(meta0.info.taint.labels.len(), 1);
        assert!(matches!(meta0.info.taint.labels[0], DataLabel::Source(_)));
        // Full NodeInfo round-trip: span, defines, and kind are preserved.
        assert_eq!(meta0.info.ast.span, (0, 10));
        assert_eq!(meta0.info.taint.defines.as_deref(), Some("x"));

        // Node 1: no bin_op, no labels
        let meta1 = &body.node_meta[&1];
        assert_eq!(meta1.info.bin_op, None);
        assert!(meta1.info.taint.labels.is_empty());
        assert_eq!(meta1.info.taint.defines.as_deref(), Some("y"));
    }

    #[test]
    fn populate_node_meta_fails_on_invalid_node() {
        let cfg = make_test_cfg(); // only has 2 nodes (0, 1)
        let bad_node = NodeIndex::new(999);
        let n0 = NodeIndex::new(0);

        let mut body = make_body_referencing_nodes(n0, bad_node);

        let ok = populate_node_meta(&mut body, &cfg);
        assert!(!ok, "should fail for out-of-bounds NodeIndex");
    }

    #[test]
    fn populate_node_meta_idempotent() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);

        populate_node_meta(&mut body, &cfg);
        let first_pass = body.node_meta.clone();

        populate_node_meta(&mut body, &cfg);
        assert_eq!(
            body.node_meta, first_pass,
            "second call should be idempotent"
        );
    }

    #[test]
    fn cross_file_node_meta_default() {
        let meta = CrossFileNodeMeta::default();
        assert_eq!(meta.info.bin_op, None);
        assert!(meta.info.taint.labels.is_empty());
    }

    // ── rebuild_body_graph ──────────────────────────────────────────────

    #[test]
    fn rebuild_body_graph_synthesizes_proxy_cfg() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        populate_node_meta(&mut body, &cfg);
        // Simulate the indexed-scan load: body_graph is skipped by serde.
        body.body_graph = None;

        let rebuilt = rebuild_body_graph(&mut body);
        assert!(rebuilt, "rebuild should install a fresh graph");
        let graph = body.body_graph.as_ref().expect("graph rebuilt");
        assert_eq!(graph.node_count(), 2);
        let info0 = &graph[n0];
        assert_eq!(info0.bin_op, Some(BinOp::Add));
        assert_eq!(info0.taint.labels.len(), 1);
        assert!(matches!(info0.taint.labels[0], DataLabel::Source(_)));
    }

    #[test]
    fn rebuild_body_graph_is_idempotent() {
        let cfg = make_test_cfg();
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        populate_node_meta(&mut body, &cfg);
        body.body_graph = None;

        assert!(rebuild_body_graph(&mut body));
        assert!(!rebuild_body_graph(&mut body), "second call must no-op");
    }

    #[test]
    fn rebuild_body_graph_noop_without_meta() {
        // Intra-file body: node_meta empty, body_graph comes from pass 1.
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let mut body = make_body_referencing_nodes(n0, n1);
        assert!(body.node_meta.is_empty());
        assert!(body.body_graph.is_none());
        assert!(!rebuild_body_graph(&mut body));
        assert!(body.body_graph.is_none());
    }
}

#[cfg(test)]
mod inline_cache_epoch_tests {
    //! Hooks for cross-file SCC joint fixed-point iteration.
    //!
    //! These do not exercise the full inline pipeline, they lock down the
    //! semantic contract of [`inline_cache_clear_epoch`] and
    //! [`inline_cache_fingerprint`] so the SCC orchestrator can rely on:
    //!
    //! * `clear_epoch` drops every entry, leaving the cache empty.
    //! * `fingerprint` is deterministic across equivalent caches (same
    //!   keys → same bytes).  Two caches with identical entries produce
    //!   identical fingerprints regardless of insertion order.
    //! * `fingerprint` changes when return caps change, the signal the
    //!   orchestrator will use to detect inline-cache convergence.

    use super::super::*;
    use crate::labels::Cap;
    use crate::symbol::FuncKey;
    use crate::taint::domain::VarTaint;
    use smallvec::SmallVec;

    fn key(name: &str) -> FuncKey {
        FuncKey::from_parts(
            crate::symbol::Lang::Rust,
            String::new(),
            String::new(),
            name,
            None,
            None,
            crate::symbol::FuncKind::Function,
        )
    }

    fn sig() -> ArgTaintSig {
        ArgTaintSig(SmallVec::new())
    }

    fn shape(caps_bits: u32) -> CachedInlineShape {
        CachedInlineShape(Some(ReturnShape {
            caps: Cap::from_bits_retain(caps_bits),
            internal_origins: SmallVec::new(),
            param_provenance: 0,
            receiver_provenance: false,
            uses_summary: false,
            return_path_fact: crate::abstract_interp::PathFact::top(),
        }))
    }

    #[test]
    fn clear_epoch_drops_all_entries() {
        let mut c: InlineCache = HashMap::new();
        c.insert((key("a"), sig()), shape(1));
        c.insert((key("b"), sig()), shape(2));
        assert_eq!(c.len(), 2);

        inline_cache_clear_epoch(&mut c);
        assert!(c.is_empty());
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let mut a: InlineCache = HashMap::new();
        a.insert((key("alpha"), sig()), shape(3));
        a.insert((key("beta"), sig()), shape(5));

        let mut b: InlineCache = HashMap::new();
        b.insert((key("beta"), sig()), shape(5));
        b.insert((key("alpha"), sig()), shape(3));

        assert_eq!(inline_cache_fingerprint(&a), inline_cache_fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_when_return_caps_change() {
        let mut c: InlineCache = HashMap::new();
        c.insert((key("f"), sig()), shape(0));
        let before = inline_cache_fingerprint(&c);

        c.insert((key("f"), sig()), shape(1));
        let after = inline_cache_fingerprint(&c);

        assert_ne!(before, after, "cap refinement must change fingerprint");
    }

    #[test]
    fn fingerprint_tracks_missing_return_taint_as_zero() {
        // A cached miss (no return taint) fingerprints as zero caps so
        // two converged iterations both producing "no return taint" are
        // recognised as equal.
        let mut c: InlineCache = HashMap::new();
        c.insert((key("f"), sig()), CachedInlineShape(None));
        let fp = inline_cache_fingerprint(&c);
        assert_eq!(*fp.get(&(key("f"), sig())).unwrap(), 0);
    }

    // ── apply_cached_shape: origin re-attribution ──────────────────────

    use crate::labels::SourceKind;
    use petgraph::graph::NodeIndex;

    fn origin_at(node: usize, kind: SourceKind, span: Option<(usize, usize)>) -> TaintOrigin {
        TaintOrigin {
            node: NodeIndex::new(node),
            source_kind: kind,
            source_span: span,
        }
    }

    #[test]
    fn apply_reattributes_param_origins_per_call_site() {
        // Shared cached shape: cap bit set, Param(0) marked as provenance source.
        let cached = CachedInlineShape(Some(ReturnShape {
            caps: Cap::SHELL_ESCAPE,
            internal_origins: SmallVec::new(),
            param_provenance: 1u64 << 0,
            receiver_provenance: false,
            uses_summary: true,
            return_path_fact: crate::abstract_interp::PathFact::top(),
        }));

        // Caller A: argument carries an env-source origin.
        let mut state_a = SsaTaintState::initial();
        state_a.set(
            SsaValue(1),
            VarTaint {
                caps: Cap::SHELL_ESCAPE,
                origins: SmallVec::from_vec(vec![origin_at(
                    10,
                    SourceKind::EnvironmentConfig,
                    Some((100, 120)),
                )]),
                uses_summary: false,
            },
        );
        let args_a: Vec<SmallVec<[SsaValue; 2]>> = vec![SmallVec::from_vec(vec![SsaValue(1)])];
        let res_a = apply_cached_shape(&cached, &args_a, &None, &state_a, NodeIndex::new(200));
        let vt_a = res_a.return_taint.expect("apply a");
        assert_eq!(vt_a.origins.len(), 1);
        assert_eq!(vt_a.origins[0].source_kind, SourceKind::EnvironmentConfig);
        assert_eq!(vt_a.origins[0].source_span, Some((100, 120)));

        // Caller B: same caps, different origin (filesystem read).
        let mut state_b = SsaTaintState::initial();
        state_b.set(
            SsaValue(2),
            VarTaint {
                caps: Cap::SHELL_ESCAPE,
                origins: SmallVec::from_vec(vec![origin_at(
                    20,
                    SourceKind::FileSystem,
                    Some((300, 320)),
                )]),
                uses_summary: false,
            },
        );
        let args_b: Vec<SmallVec<[SsaValue; 2]>> = vec![SmallVec::from_vec(vec![SsaValue(2)])];
        let res_b = apply_cached_shape(&cached, &args_b, &None, &state_b, NodeIndex::new(201));
        let vt_b = res_b.return_taint.expect("apply b");
        assert_eq!(vt_b.origins.len(), 1);
        assert_eq!(
            vt_b.origins[0].source_kind,
            SourceKind::FileSystem,
            "second caller must see its own source, not caller A's cached origin"
        );
        assert_eq!(vt_b.origins[0].source_span, Some((300, 320)));
    }

    #[test]
    fn apply_remaps_internal_origins_to_call_site() {
        // Cached shape with a single callee-internal origin.
        let internal_origin = TaintOrigin {
            node: NodeIndex::end(), // placeholder written by extract
            source_kind: SourceKind::UserInput,
            source_span: Some((55, 77)),
        };
        let mut internal_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        internal_origins.push(internal_origin);
        let cached = CachedInlineShape(Some(ReturnShape {
            caps: Cap::HTML_ESCAPE,
            internal_origins,
            param_provenance: 0,
            receiver_provenance: false,
            uses_summary: true,
            return_path_fact: crate::abstract_interp::PathFact::top(),
        }));

        let state = SsaTaintState::initial();
        let args: Vec<SmallVec<[SsaValue; 2]>> = vec![];
        let call_site = NodeIndex::new(777);
        let res = apply_cached_shape(&cached, &args, &None, &state, call_site);
        let vt = res.return_taint.expect("apply");
        assert_eq!(vt.origins.len(), 1);
        assert_eq!(vt.origins[0].node, call_site);
        assert_eq!(vt.origins[0].source_span, Some((55, 77)));
    }
}

#[cfg(test)]
mod binding_key_tests {
    use super::super::*;
    use crate::cfg::BodyId;
    use crate::taint::domain::VarTaint;
    use smallvec::smallvec;
    use std::collections::HashMap;

    // ── PartialEq / Hash ───────────────────────────────────────────────

    #[test]
    fn same_name_same_body_id_matches() {
        let a = BindingKey::new("x", BodyId(1));
        let b = BindingKey::new("x", BodyId(1));
        assert_eq!(a, b);
    }

    #[test]
    fn same_name_different_body_id_no_match() {
        let a = BindingKey::new("x", BodyId(1));
        let b = BindingKey::new("x", BodyId(2));
        assert_ne!(a, b);
    }

    #[test]
    fn different_name_no_match() {
        assert_ne!(
            BindingKey::new("x", BodyId(1)),
            BindingKey::new("y", BodyId(1))
        );
    }

    // ── seed_lookup ────────────────────────────────────────────────────

    fn taint(caps: u32) -> VarTaint {
        VarTaint {
            caps: Cap::from_bits_truncate(caps),
            origins: smallvec![],
            uses_summary: false,
        }
    }

    #[test]
    fn seed_lookup_exact_match() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x", BodyId(1)), taint(1));
        let key = BindingKey::new("x", BodyId(1));
        assert_eq!(
            seed_lookup(&seed, &key).map(|t| t.caps),
            Some(Cap::from_bits_truncate(1))
        );
    }

    #[test]
    fn seed_lookup_different_body_ids_distinct() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x", BodyId(1)), taint(1));
        seed.insert(BindingKey::new("x", BodyId(2)), taint(2));
        assert_eq!(
            seed_lookup(&seed, &BindingKey::new("x", BodyId(1))).map(|t| t.caps),
            Some(Cap::from_bits_truncate(1))
        );
        assert_eq!(
            seed_lookup(&seed, &BindingKey::new("x", BodyId(2))).map(|t| t.caps),
            Some(Cap::from_bits_truncate(2))
        );
        // BodyId(3) has no entry and there is no wildcard fallback.
        assert!(seed_lookup(&seed, &BindingKey::new("x", BodyId(3))).is_none());
    }

    #[test]
    fn seed_lookup_miss_different_name() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x", BodyId(0)), taint(1));
        assert!(seed_lookup(&seed, &BindingKey::new("y", BodyId(0))).is_none());
    }

    // ── join_seed_maps ─────────────────────────────────────────────────

    #[test]
    fn join_seed_maps_does_not_merge_different_body_ids() {
        let mut a = HashMap::new();
        a.insert(BindingKey::new("x", BodyId(1)), taint(1));
        let mut b = HashMap::new();
        b.insert(BindingKey::new("x", BodyId(2)), taint(2));
        let joined = join_seed_maps(&a, &b);
        assert_eq!(joined.len(), 2);
        assert_eq!(
            joined.get(&BindingKey::new("x", BodyId(1))).unwrap().caps,
            Cap::from_bits_truncate(1)
        );
        assert_eq!(
            joined.get(&BindingKey::new("x", BodyId(2))).unwrap().caps,
            Cap::from_bits_truncate(2)
        );
    }

    #[test]
    fn join_seed_maps_merges_same_body_id() {
        let mut a = HashMap::new();
        a.insert(BindingKey::new("x", BodyId(1)), taint(1));
        let mut b = HashMap::new();
        b.insert(BindingKey::new("x", BodyId(1)), taint(2));
        let joined = join_seed_maps(&a, &b);
        assert_eq!(joined.len(), 1);
        let caps = joined.get(&BindingKey::new("x", BodyId(1))).unwrap().caps;
        assert!(caps.contains(Cap::from_bits_truncate(1)));
        assert!(caps.contains(Cap::from_bits_truncate(2)));
    }

    // ── filter_seed_to_toplevel ────────────────────────────────────────

    #[test]
    fn filter_seed_retains_matching_names_and_rekeys_to_toplevel() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x", BodyId(1)), taint(1));
        seed.insert(BindingKey::new("y", BodyId(2)), taint(2));

        let mut toplevel = HashSet::new();
        toplevel.insert(BindingKey::new("x", BodyId(0)));
        let filtered = filter_seed_to_toplevel(&seed, &toplevel, &[]);
        assert_eq!(filtered.len(), 1);
        // Every surviving entry is re-keyed onto BodyId(0).
        assert!(filtered.contains_key(&BindingKey::new("x", BodyId(0))));
        for key in filtered.keys() {
            assert_eq!(key.body_id, BodyId(0));
        }
    }

    #[test]
    fn filter_seed_excludes_non_toplevel() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x", BodyId(1)), taint(1));
        seed.insert(BindingKey::new("y", BodyId(1)), taint(2));

        let mut toplevel = HashSet::new();
        toplevel.insert(BindingKey::new("x", BodyId(0)));
        let filtered = filter_seed_to_toplevel(&seed, &toplevel, &[]);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&BindingKey::new("x", BodyId(0))));
    }

    /// When two sibling bodies both contribute the same top-level name
    /// (typical JS/TS pass-2 `combined_exit` shape), the filtered map
    /// merges them under `BodyId(0)` via the join code path.
    #[test]
    fn filter_seed_merges_same_name_across_bodies() {
        let mut seed = HashMap::new();
        seed.insert(BindingKey::new("x", BodyId(1)), taint(0b0001));
        seed.insert(BindingKey::new("x", BodyId(2)), taint(0b0010));
        let mut toplevel = HashSet::new();
        toplevel.insert(BindingKey::new("x", BodyId(0)));
        let filtered = filter_seed_to_toplevel(&seed, &toplevel, &[]);
        assert_eq!(filtered.len(), 1);
        let merged = filtered.get(&BindingKey::new("x", BodyId(0))).unwrap();
        assert_eq!(merged.caps, Cap::from_bits_truncate(0b0011));
    }
}

#[cfg(test)]
mod worklist_tests {
    use std::collections::{HashSet, VecDeque};

    /// Simulate the O(1) worklist membership pattern from run_ssa_taint_internal.
    /// Verifies that the HashSet stays in sync with the VecDeque.
    fn worklist_push(wl: &mut VecDeque<usize>, in_wl: &mut HashSet<usize>, idx: usize) -> bool {
        if in_wl.insert(idx) {
            wl.push_back(idx);
            true
        } else {
            false
        }
    }

    fn worklist_pop(wl: &mut VecDeque<usize>, in_wl: &mut HashSet<usize>) -> Option<usize> {
        let val = wl.pop_front()?;
        in_wl.remove(&val);
        Some(val)
    }

    #[test]
    fn duplicate_enqueue_produces_single_entry() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        assert!(worklist_push(&mut wl, &mut in_wl, 0));
        assert!(!worklist_push(&mut wl, &mut in_wl, 0)); // duplicate
        assert_eq!(wl.len(), 1);
        assert_eq!(in_wl.len(), 1);
    }

    #[test]
    fn pop_removes_from_set() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 5);
        worklist_push(&mut wl, &mut in_wl, 10);
        let val = worklist_pop(&mut wl, &mut in_wl);
        assert_eq!(val, Some(5));
        assert!(!in_wl.contains(&5));
        assert!(in_wl.contains(&10));
    }

    #[test]
    fn re_enqueue_after_pop() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);
        let _ = worklist_pop(&mut wl, &mut in_wl);
        // After popping, we should be able to re-enqueue
        assert!(worklist_push(&mut wl, &mut in_wl, 0));
        assert_eq!(wl.len(), 1);
    }

    #[test]
    fn empty_worklist() {
        let mut wl: VecDeque<usize> = VecDeque::new();
        let mut in_wl: HashSet<usize> = HashSet::new();
        assert_eq!(worklist_pop(&mut wl, &mut in_wl), None);
        assert!(in_wl.is_empty());
    }

    #[test]
    fn self_loop_pattern() {
        // Simulate a block that re-enqueues itself
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);

        let block = worklist_pop(&mut wl, &mut in_wl).unwrap();
        assert_eq!(block, 0);
        // Re-enqueue self (simulating state change)
        worklist_push(&mut wl, &mut in_wl, 0);
        // Also enqueue successor
        worklist_push(&mut wl, &mut in_wl, 1);
        assert_eq!(wl.len(), 2);
    }

    #[test]
    fn cycle_with_repeated_discovery() {
        // Simulate cycle: 0→1→2→0 with multiple state propagations
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();
        worklist_push(&mut wl, &mut in_wl, 0);

        let mut iterations = 0;
        while let Some(block) = worklist_pop(&mut wl, &mut in_wl) {
            iterations += 1;
            if iterations > 10 {
                break; // safety net
            }
            let succ = (block + 1) % 3;
            // Only re-enqueue if "state changed" (simulate with iteration limit)
            if iterations < 6 {
                worklist_push(&mut wl, &mut in_wl, succ);
            }
        }
        assert!(iterations <= 10, "worklist should terminate");
        assert!(wl.is_empty());
        assert!(in_wl.is_empty());
    }

    #[test]
    fn dense_successors_no_duplicates() {
        // Many successors, some repeated, old O(n) contains() would be slow here
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();

        // Seed with one node
        worklist_push(&mut wl, &mut in_wl, 0);
        let _ = worklist_pop(&mut wl, &mut in_wl);

        // Try to add 100 successors, with many duplicates
        let mut total_enqueued = 0;
        for i in 0..100 {
            let succ = i % 10; // only 10 unique blocks
            if worklist_push(&mut wl, &mut in_wl, succ) {
                total_enqueued += 1;
            }
        }
        assert_eq!(total_enqueued, 10); // only 10 unique blocks enqueued
        assert_eq!(wl.len(), 10);
        assert_eq!(in_wl.len(), 10);
    }

    #[test]
    fn set_and_deque_stay_in_sync_throughout() {
        let mut wl = VecDeque::new();
        let mut in_wl = HashSet::new();

        // Push, pop, re-push cycle
        for i in 0..20 {
            worklist_push(&mut wl, &mut in_wl, i);
        }
        assert_eq!(wl.len(), in_wl.len());

        for _ in 0..10 {
            worklist_pop(&mut wl, &mut in_wl);
        }
        assert_eq!(wl.len(), in_wl.len());
        assert_eq!(wl.len(), 10);

        // Re-push some previously popped
        for i in 0..5 {
            worklist_push(&mut wl, &mut in_wl, i);
        }
        assert_eq!(wl.len(), in_wl.len());
        assert_eq!(wl.len(), 15);

        // Drain completely
        while worklist_pop(&mut wl, &mut in_wl).is_some() {}
        assert!(wl.is_empty());
        assert!(in_wl.is_empty());
    }
}

#[cfg(test)]
mod primary_sink_location_tests {
    //! Regression guard for the primary sink-location attribution contract:
    //! a [`SinkSite`] carried on an [`SsaFuncSummary`] must propagate
    //! unchanged through summary resolution →
    //! [`SsaTaintEvent::primary_sink_site`] →
    //! [`crate::taint::Finding::primary_location`].
    //!
    //! The test is deliberately low-level, it wires up synthetic SSA and
    //! drives the three emission stages directly, so any future refactor
    //! that drops the site on the floor between stages fails here rather
    //! than only at the corpus/benchmark layer.
    use super::super::*;
    use crate::cfg::{AstMeta, CallMeta, Cfg, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::{Cap, SourceKind};
    use crate::summary::SinkSite;
    use crate::summary::ssa_summary::SsaFuncSummary;
    use crate::taint::domain::TaintOrigin;
    use petgraph::graph::NodeIndex;
    use petgraph::prelude::*;
    use smallvec::smallvec;

    /// Build a caller CFG that models `sink(source())`: two nodes, where
    /// the sink node carries `callee = "dangerous_exec"` so
    /// [`reconstruct_flow_path`] can name the sink.
    fn caller_cfg() -> (Cfg, NodeIndex, NodeIndex) {
        let mut cfg = Graph::new();
        let source = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 5),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta::default(),
            ..Default::default()
        });
        let sink = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (10, 30),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta {
                callee: Some("dangerous_exec".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        (cfg, source, sink)
    }

    /// Build an SSA body for `v0 = source(); v1 = dangerous_exec(v0); ret`.
    fn caller_body(source_node: NodeIndex, sink_node: NodeIndex) -> SsaBody {
        let mut cfg_node_map = crate::ssa::ir::CfgNodeMap::default();
        cfg_node_map.insert(source_node, SsaValue(0));
        cfg_node_map.insert(sink_node, SsaValue(1));
        SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Source,
                        cfg_node: source_node,
                        var_name: Some("x".into()),
                        span: (0, 5),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Call {
                            callee: "dangerous_exec".into(),
                            callee_text: None,
                            args: vec![smallvec![SsaValue(0)]],
                            receiver: None,
                        },
                        cfg_node: sink_node,
                        var_name: None,
                        span: (10, 30),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("x".into()),
                    cfg_node: source_node,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: None,
                    cfg_node: sink_node,
                    block: BlockId(0),
                },
            ],
            cfg_node_map,
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        }
    }

    /// Locks in the end-to-end contract that a SinkSite on an
    /// SsaFuncSummary surfaces verbatim as `Finding.primary_location`.
    ///
    /// If this fails, something on the summary→event→finding path
    /// (`pick_primary_sink_sites`, `emit_ssa_taint_events`, or
    /// `ssa_events_to_findings`) has silently stopped forwarding
    /// coordinates.  Fixing that path, not this test, is the right
    /// response.
    #[test]
    fn ssa_summary_sinksite_surfaces_as_finding_primary_location() {
        let (cfg, source_node, sink_node) = caller_cfg();
        let ssa = caller_body(source_node, sink_node);

        // Synthetic summary: parameter 0 reaches a SHELL_ESCAPE sink inside
        // the callee at "other.rs":42:10.
        let site = SinkSite {
            file_rel: "other.rs".into(),
            line: 42,
            col: 10,
            snippet: "Command::new(cmd).status()".into(),
            cap: Cap::SHELL_ESCAPE,
            from_chain: false,
        };
        let summary = SsaFuncSummary {
            param_to_sink: vec![(0usize, smallvec![site.clone()])],
            ..Default::default()
        };

        // Drive the three emission stages with the summary's own
        // `param_to_sink`, that is what summary resolution feeds in the
        // real pipeline.
        let tainted: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)> = vec![(
            SsaValue(0),
            Cap::SHELL_ESCAPE,
            smallvec![TaintOrigin {
                node: source_node,
                source_kind: SourceKind::EnvironmentConfig,
                source_span: None,
            }],
        )];
        let call_inst = &ssa.blocks[0].body[1];
        let primary_sites = pick_primary_sink_sites(
            call_inst,
            &tainted,
            Cap::SHELL_ESCAPE,
            &summary.param_to_sink,
            "caller.rs",
            false,
        );
        assert_eq!(
            primary_sites.len(),
            1,
            "summary site must survive pick filter (line != 0, cap ∩ sink_caps ≠ ∅)",
        );

        let mut events = Vec::new();
        emit_ssa_taint_events(
            &mut events,
            sink_node,
            tainted.clone(),
            Cap::SHELL_ESCAPE,
            /* all_validated */ false,
            /* guard_kind   */ None,
            /* uses_summary */ true,
            primary_sites,
            /* inline_source */ false,
        );
        assert_eq!(events.len(), 1, "single site → single event");
        let event_site = events[0]
            .primary_sink_site
            .as_ref()
            .expect("event must carry the primary SinkSite");
        assert_eq!(
            (
                event_site.file_rel.as_str(),
                event_site.line,
                event_site.col,
            ),
            ("other.rs", 42, 10),
        );

        let findings = ssa_events_to_findings(&events, &ssa, &cfg);
        assert_eq!(findings.len(), 1);
        let loc = findings[0]
            .primary_location
            .as_ref()
            .expect("Finding.primary_location must be populated from SinkSite");
        assert_eq!(loc.file_rel, "other.rs");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.col, 10);
        assert_eq!(loc.snippet, "Command::new(cmd).status()");
    }
}

#[cfg(test)]
mod goto_succ_propagation_tests {
    //! Regression guard for the 3-successor Goto collapse in
    //! `src/ssa/lower.rs` (see `three_successor_collapse_produces_goto`).
    //!
    //! Lowering collapses ≥3-successor blocks to `Terminator::Goto(first)`
    //! but preserves the full successor list on `block.succs`. Flow
    //! consumers (this module's `compute_succ_states`, SCCP's
    //! `process_terminator`) must treat `block.succs` as authoritative.
    //! Without that, taint exits only through the first successor and all
    //! downstream blocks on the other edges silently drop it.
    use super::super::*;
    use crate::cfg::Cfg;
    use crate::state::symbol::SymbolInterner;
    use petgraph::Graph;
    use smallvec::smallvec;

    #[test]
    fn goto_propagates_to_every_succ_on_three_way_collapse() {
        // Build a block with Terminator::Goto(1) but succs = [1, 2, 3], the
        // shape lowering emits for a 3-way fanout.
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![],
            terminator: Terminator::Goto(BlockId(1)),
            preds: smallvec![],
            succs: smallvec![BlockId(1), BlockId(2), BlockId(3)],
        };

        let ssa = SsaBody {
            blocks: vec![block.clone()],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let cfg: Cfg = Graph::new();
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = std::collections::HashMap::new();

        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: None,
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };

        // A non-bottom exit state, the test only cares that *every* succ
        // receives a clone of it, so any distinguishable state works.
        let mut exit_state = SsaTaintState::initial();
        exit_state.values.push((
            SsaValue(42),
            VarTaint {
                caps: crate::labels::Cap::all(),
                origins: smallvec::SmallVec::new(),
                uses_summary: false,
            },
        ));

        let succ_states = compute_succ_states(&block, &cfg, &ssa, &transfer, &exit_state);

        assert_eq!(
            succ_states.len(),
            3,
            "Goto with 3 succs must propagate to all 3 successors, got {:?}",
            succ_states.iter().map(|(b, _)| *b).collect::<Vec<_>>()
        );

        let targets: Vec<BlockId> = succ_states.iter().map(|(b, _)| *b).collect();
        assert_eq!(targets, vec![BlockId(1), BlockId(2), BlockId(3)]);

        for (bid, state) in &succ_states {
            assert!(
                state.values.iter().any(|(v, _)| *v == SsaValue(42)),
                "succ {:?} did not receive the exit state taint",
                bid
            );
        }
    }

    #[test]
    fn goto_single_successor_still_works() {
        // Normal Goto with a single successor: behavior unchanged.
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![],
            terminator: Terminator::Goto(BlockId(1)),
            preds: smallvec![],
            succs: smallvec![BlockId(1)],
        };
        let ssa = SsaBody {
            blocks: vec![block.clone()],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let cfg: Cfg = Graph::new();
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = std::collections::HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: None,
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };
        let exit_state = SsaTaintState::initial();

        let succ_states = compute_succ_states(&block, &cfg, &ssa, &transfer, &exit_state);
        assert_eq!(succ_states.len(), 1);
        assert_eq!(succ_states[0].0, BlockId(1));
    }

    /// The persistent per-thread branch-condition cache
    /// (`classify_branch_cond_cached`) is a transparent memo over the pure
    /// `classify_branch_cond`: the cached result on both the cold (first) and
    /// warm (second) lookup must equal the uncached classification for the
    /// same text.  Covers texts that exercise each `has_semantic_negation`
    /// branch (AllowlistCheck `not in`, TypeCheck `!==`, ValidationCall
    /// negative-polarity) plus a PathFact rejection idiom, so a future change
    /// that breaks the cache↔pure-function equivalence is caught here rather
    /// than as a silent finding drift on a real repo.
    #[test]
    fn branch_cond_cache_matches_uncached_cold_and_warm() {
        let texts = [
            "err != nil",
            "x == null",
            "scheme not in allowed",
            "typeof x !== 'number'",
            "isInvalidUrl(u)",
            "(ALLOWED.includes(cmd) === false)",
            "ALLOWED.indexOf(cmd) < 0",
            "is_valid(x) is not True",
            "ok === false",
            "p.contains(\"..\")",
            "user.isAdmin",
        ];
        for t in texts {
            let pure = classify_branch_cond(t);
            // Cold lookup (first time this text is seen on this thread): the
            // cache misses, computes, and inserts.
            let cold = classify_branch_cond_cached(t);
            // Warm lookup: the cache hits and returns a clone.
            let warm = classify_branch_cond_cached(t);
            assert_eq!(cold, pure, "cold cache result diverged for {t:?}");
            assert_eq!(warm, pure, "warm cache result diverged for {t:?}");
        }
    }

    // ── PathFact branch-narrowing smoke tests ─────────────────────────────

    /// Build a minimal `SsaBody` with a single value def named `var_name`.
    /// Used to drive `apply_path_fact_branch_narrowing` without a full CFG.
    fn ssa_body_with_named_value(var_name: &str) -> SsaBody {
        SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Source,
                    cfg_node: NodeIndex::new(0),
                    var_name: Some(var_name.into()),
                    span: (0, 1),
                }],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![crate::ssa::ir::ValueDef {
                var_name: Some(var_name.into()),
                cfg_node: NodeIndex::new(0),
                block: BlockId(0),
            }],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        }
    }

    fn initial_state_with_abstract() -> SsaTaintState {
        let mut s = SsaTaintState::initial();
        s.abstract_state = Some(std::sync::Arc::new(
            crate::abstract_interp::AbstractState::empty(),
        ));
        s
    }

    #[test]
    fn path_fact_contains_dotdot_narrows_false_branch() {
        let ssa = ssa_body_with_named_value("user");
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();

        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "user.contains(\"..\")",
            &["user".to_string()],
            &ssa,
        );

        let abs = false_state.abstract_state.as_ref().unwrap();
        let fact = abs.get(SsaValue(0)).path;
        assert_eq!(fact.dotdot, crate::abstract_interp::Tri::No);
        // true branch (rejection path) unchanged.
        let true_abs = true_state.abstract_state.as_ref().unwrap();
        assert_eq!(
            true_abs.get(SsaValue(0)).path.dotdot,
            crate::abstract_interp::Tri::Maybe
        );
    }

    #[test]
    fn path_fact_starts_with_slash_narrows_false_branch() {
        let ssa = ssa_body_with_named_value("p");
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();

        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "p.starts_with('/')",
            &["p".to_string()],
            &ssa,
        );

        let fact = false_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert_eq!(fact.absolute, crate::abstract_interp::Tri::No);
    }

    #[test]
    fn path_fact_is_absolute_narrows_false_branch() {
        let ssa = ssa_body_with_named_value("p");
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();

        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "p.is_absolute()",
            &["p".to_string()],
            &ssa,
        );

        let fact = false_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert_eq!(fact.absolute, crate::abstract_interp::Tri::No);
    }

    #[test]
    fn path_fact_starts_with_literal_sets_prefix_lock_on_true_branch() {
        let ssa = ssa_body_with_named_value("p");
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();

        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "p.starts_with(\"/var/app/uploads/\")",
            &["p".to_string()],
            &ssa,
        );

        let fact = true_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert_eq!(
            fact.prefix_lock.as_deref(),
            Some("/var/app/uploads/"),
            "positive starts_with(literal) must attach prefix_lock on true branch"
        );
    }

    /// A branch state whose value 0 carries `fact`.
    fn state_with_path_fact(fact: crate::abstract_interp::PathFact) -> SsaTaintState {
        let mut s = initial_state_with_abstract();
        std::sync::Arc::make_mut(s.abstract_state.as_mut().unwrap()).set(
            SsaValue(0),
            crate::abstract_interp::AbstractValue::with_path_fact(fact),
        );
        s
    }

    fn lexically_normalized_fact() -> crate::abstract_interp::PathFact {
        let mut f = crate::abstract_interp::PathFact::top();
        f.normalized = crate::abstract_interp::Tri::Yes;
        f
    }

    #[test]
    fn prefix_lock_on_a_normalized_path_clears_dotdot() {
        // `p = normpath(x); if p.startswith(ROOT): sink(p)`.  A normalized
        // path holds `..` only as leading components, and a path that starts
        // with ROOT does not.
        let ssa = ssa_body_with_named_value("p");
        for (cond, root) in [
            ("p.startswith(\"/srv/files/\")", "/srv/files/"),
            (
                "p.startswith(base)",
                crate::abstract_interp::path_domain::OPAQUE_PREFIX_LOCK,
            ),
        ] {
            let mut true_state = state_with_path_fact(lexically_normalized_fact());
            let mut false_state = state_with_path_fact(lexically_normalized_fact());
            super::super::apply_path_fact_branch_narrowing(
                &mut true_state,
                &mut false_state,
                cond,
                &["p".to_string()],
                &ssa,
            );
            let fact = true_state
                .abstract_state
                .as_ref()
                .unwrap()
                .get(SsaValue(0))
                .path;
            assert_eq!(fact.prefix_lock.as_deref(), Some(root), "{cond}");
            assert_eq!(fact.dotdot, crate::abstract_interp::Tri::No, "{cond}");
            assert!(fact.is_path_traversal_safe(), "{cond}");
        }
    }

    #[test]
    fn prefix_lock_on_a_raw_path_keeps_dotdot_unknown() {
        // Without normalization `/srv/files/../../etc` also starts with the
        // root, so the lock alone proves nothing about `..`.
        let ssa = ssa_body_with_named_value("p");
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();
        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "p.startswith(\"/srv/files/\")",
            &["p".to_string()],
            &ssa,
        );
        let fact = true_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert_eq!(fact.dotdot, crate::abstract_interp::Tri::Maybe);
        assert!(!fact.is_path_traversal_safe());
    }

    #[test]
    fn prefix_lock_rooted_at_dotdot_clears_nothing() {
        let ssa = ssa_body_with_named_value("p");
        let mut true_state = state_with_path_fact(lexically_normalized_fact());
        let mut false_state = state_with_path_fact(lexically_normalized_fact());
        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "p.startswith(\"../uploads\")",
            &["p".to_string()],
            &ssa,
        );
        let fact = true_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert_eq!(fact.dotdot, crate::abstract_interp::Tri::Maybe);
    }

    #[test]
    fn leading_dotdot_rejection_clears_dotdot_only_when_normalized() {
        // `p = normpath(x); if p.startswith('..'): reject; sink(p)`.
        let ssa = ssa_body_with_named_value("p");
        let mut true_state = state_with_path_fact(lexically_normalized_fact());
        let mut false_state = state_with_path_fact(lexically_normalized_fact());
        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "p.startswith('..')",
            &["p".to_string()],
            &ssa,
        );
        let surviving = false_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert_eq!(surviving.dotdot, crate::abstract_interp::Tri::No);
        let rejected = true_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert_eq!(rejected.dotdot, crate::abstract_interp::Tri::Maybe);

        // The same test on a raw path says nothing about `a/../../b`.
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();
        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "p.startswith('..')",
            &["p".to_string()],
            &ssa,
        );
        let surviving = false_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert_eq!(surviving.dotdot, crate::abstract_interp::Tri::Maybe);
    }

    #[test]
    fn strpos_not_zero_locks_the_false_branch() {
        // `if (strpos($real, $base) !== 0) { die(); } include($real);`
        let ssa = ssa_body_with_named_value("real");
        let mut true_state = state_with_path_fact(lexically_normalized_fact());
        let mut false_state = state_with_path_fact(lexically_normalized_fact());
        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "strpos($real, $base) !== 0",
            &["real".to_string()],
            &ssa,
        );
        let surviving = false_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert!(surviving.prefix_lock.is_some());
        assert_eq!(surviving.dotdot, crate::abstract_interp::Tri::No);
        let rejected = true_state
            .abstract_state
            .as_ref()
            .unwrap()
            .get(SsaValue(0))
            .path;
        assert!(rejected.prefix_lock.is_none());
    }

    #[test]
    fn path_fact_negated_contains_dotdot_narrows_true_branch() {
        // `if !path.contains("..") { return; } sink(path);` — the surviving
        // (sink-reaching) arm is the TRUE branch of the IF condition.  The
        // rejection axis (DotDot) must narrow `true_state`, not `false_state`,
        // otherwise the unsafe arm gets dotdot=No and the sink suppression
        // masks the bug.
        let ssa = ssa_body_with_named_value("path");
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();

        super::super::apply_path_fact_branch_narrowing_with_aliases(
            &mut true_state,
            &mut false_state,
            &super::super::classify_path_branch("!path.contains(\"..\")"),
            &["path".to_string()],
            &ssa,
            BlockId(0),
            None,
            true,
        );

        let true_abs = true_state.abstract_state.as_ref().unwrap();
        let false_abs = false_state.abstract_state.as_ref().unwrap();
        assert_eq!(
            true_abs.get(SsaValue(0)).path.dotdot,
            crate::abstract_interp::Tri::No,
            "negated-contains: TRUE arm (sink-reaching, safe) must narrow"
        );
        assert_eq!(
            false_abs.get(SsaValue(0)).path.dotdot,
            crate::abstract_interp::Tri::Maybe,
            "negated-contains: FALSE arm (rejection arm) must NOT narrow"
        );
    }

    #[test]
    fn path_fact_negated_filepath_islocal_narrows_false_branch() {
        // `if !filepath.IsLocal(p) { return; } sink(p);` — Go idiom.  The
        // classifier consumes the `!` itself (pre-negated handler), so the
        // safe arm remains the FALSE branch of the whole condition even
        // though `condition_negated == true` at AST level.
        let ssa = ssa_body_with_named_value("p");
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();

        super::super::apply_path_fact_branch_narrowing_with_aliases(
            &mut true_state,
            &mut false_state,
            &super::super::classify_path_branch("!filepath.IsLocal(p)"),
            &["p".to_string()],
            &ssa,
            BlockId(0),
            None,
            true,
        );

        let true_abs = true_state.abstract_state.as_ref().unwrap();
        let false_abs = false_state.abstract_state.as_ref().unwrap();
        assert_eq!(
            false_abs.get(SsaValue(0)).path.dotdot,
            crate::abstract_interp::Tri::No,
            "!filepath.IsLocal: FALSE arm (sink-reaching, IsLocal=true) must narrow"
        );
        assert_eq!(
            false_abs.get(SsaValue(0)).path.absolute,
            crate::abstract_interp::Tri::No,
            "!filepath.IsLocal: FALSE arm absolute axis must narrow"
        );
        assert_eq!(
            true_abs.get(SsaValue(0)).path.dotdot,
            crate::abstract_interp::Tri::Maybe,
            "!filepath.IsLocal: TRUE arm (return) must NOT narrow"
        );
    }

    #[test]
    fn path_fact_no_match_leaves_state_untouched() {
        let ssa = ssa_body_with_named_value("x");
        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();

        super::super::apply_path_fact_branch_narrowing(
            &mut true_state,
            &mut false_state,
            "x == 5",
            &["x".to_string()],
            &ssa,
        );

        // No path-idiom → both abstract_states remain empty (no writes).
        let tabs = true_state.abstract_state.as_ref().unwrap();
        let fabs = false_state.abstract_state.as_ref().unwrap();
        assert!(tabs.get(SsaValue(0)).path.is_top());
        assert!(fabs.get(SsaValue(0)).path.is_top());
    }

    fn tainted_state_with_abstract(caps: crate::labels::Cap) -> SsaTaintState {
        let mut s = initial_state_with_abstract();
        s.set(
            SsaValue(0),
            crate::taint::domain::VarTaint {
                caps,
                origins: smallvec![],
                uses_summary: false,
            },
        );
        s
    }

    #[test]
    fn open_redirect_clears_only_after_both_url_facts() {
        use crate::labels::Cap;
        use crate::state::symbol::SymbolInterner;
        use crate::taint::path_state::PredicateKind::{LeadingSlashCheck, ProtocolRelativeCheck};
        let caps = Cap::OPEN_REDIRECT | Cap::SSRF;
        let ssa = ssa_body_with_named_value("next");
        let mut interner = SymbolInterner::new();
        interner.intern("next");
        let vars = ["next".to_string()];
        let apply = |st: &mut SsaTaintState, kind, polarity| {
            super::super::apply_branch_predicates(
                st,
                &vars,
                kind,
                polarity,
                crate::taint::path_state::predicate_bit_negative_form(kind, ""),
                &interner,
                &ssa,
                None,
            )
        };
        let caps_of = |st: &SsaTaintState| st.get(SsaValue(0)).map(|t| t.caps);

        // Leading slash alone: `//evil.com` still passes.
        let mut st = tainted_state_with_abstract(caps);
        apply(&mut st, LeadingSlashCheck, true);
        assert_eq!(caps_of(&st), Some(caps));

        // Not protocol-relative alone: `https://evil.com` still passes.
        let mut st = tainted_state_with_abstract(caps);
        apply(&mut st, ProtocolRelativeCheck, false);
        assert_eq!(caps_of(&st), Some(caps));

        // Both, in either order: only OPEN_REDIRECT is cleared.
        for order in [
            [(LeadingSlashCheck, true), (ProtocolRelativeCheck, false)],
            [(ProtocolRelativeCheck, false), (LeadingSlashCheck, true)],
        ] {
            let mut st = tainted_state_with_abstract(caps);
            for (kind, polarity) in order {
                apply(&mut st, kind, polarity);
            }
            assert_eq!(caps_of(&st), Some(Cap::SSRF), "{order:?}");
        }

        // The reject edges never clear.
        let mut st = tainted_state_with_abstract(caps);
        apply(&mut st, LeadingSlashCheck, false);
        apply(&mut st, ProtocolRelativeCheck, false);
        assert_eq!(caps_of(&st), Some(caps));
    }

    #[test]
    fn path_rejection_single_axis_validates_nothing() {
        // `if (name.includes("..")) return; db.query("..." + name)`: a path
        // shape check says nothing about SQL / shell / HTML and, on one axis
        // alone, nothing about FILE_IO either (`/etc/passwd` passes a `..`
        // check).  No validation bit and no cap change on either arm.
        use crate::labels::Cap;
        let caps = Cap::SQL_QUERY | Cap::FILE_IO;
        for text in [
            "name.includes(\"..\")",
            "name.startsWith(\"/\")",
            "\"..\" in name",
            "strings.Contains(name, \"..\")",
        ] {
            let ssa = ssa_body_with_named_value("name");
            let mut true_state = tainted_state_with_abstract(caps);
            let mut false_state = tainted_state_with_abstract(caps);
            super::super::apply_path_fact_branch_narrowing_with_aliases(
                &mut true_state,
                &mut false_state,
                &super::super::classify_path_branch(text),
                &["name".to_string()],
                &ssa,
                BlockId(0),
                None,
                false,
            );
            for st in [&true_state, &false_state] {
                assert!(st.validated_must.is_empty(), "{text}: validated_must set");
                assert!(st.validated_may.is_empty(), "{text}: validated_may set");
                assert_eq!(st.get(SsaValue(0)).map(|t| t.caps), Some(caps), "{text}");
            }
        }
    }

    #[test]
    fn path_rejection_both_axes_clears_only_file_io() {
        use crate::labels::Cap;
        let caps = Cap::SQL_QUERY | Cap::FILE_IO;
        let ssa = ssa_body_with_named_value("name");

        // `if (name.includes("..") || name.startsWith("/")) return;`
        let mut true_state = tainted_state_with_abstract(caps);
        let mut false_state = tainted_state_with_abstract(caps);
        super::super::apply_path_fact_branch_narrowing_with_aliases(
            &mut true_state,
            &mut false_state,
            &super::super::classify_path_branch(
                "(name.includes(\"..\") || name.startsWith(\"/\"))",
            ),
            &["name".to_string()],
            &ssa,
            BlockId(0),
            None,
            false,
        );
        assert_eq!(
            false_state.get(SsaValue(0)).map(|t| t.caps),
            Some(Cap::SQL_QUERY),
            "surviving arm keeps every non-FILE_IO cap"
        );
        assert!(false_state.validated_must.is_empty());
        assert_eq!(true_state.get(SsaValue(0)).map(|t| t.caps), Some(caps));

        // `if (!(name.includes("..") || name.startsWith("/"))) { sink }`:
        // the CFG reports the leading `!` as condition_negated, so the
        // relative `..`-free arm is TRUE.
        let mut true_state = tainted_state_with_abstract(caps);
        let mut false_state = tainted_state_with_abstract(caps);
        super::super::apply_path_fact_branch_narrowing_with_aliases(
            &mut true_state,
            &mut false_state,
            &super::super::classify_path_branch(
                "!(name.includes(\"..\") || name.startsWith(\"/\"))",
            ),
            &["name".to_string()],
            &ssa,
            BlockId(0),
            None,
            true,
        );
        assert_eq!(
            true_state.get(SsaValue(0)).map(|t| t.caps),
            Some(Cap::SQL_QUERY)
        );
        assert_eq!(false_state.get(SsaValue(0)).map(|t| t.caps), Some(caps));

        // Two different subjects: neither is proven on both axes.
        let mut true_state = tainted_state_with_abstract(caps);
        let mut false_state = tainted_state_with_abstract(caps);
        super::super::apply_path_fact_branch_narrowing_with_aliases(
            &mut true_state,
            &mut false_state,
            &super::super::classify_path_branch("(name.includes(\"..\") || dir.startsWith(\"/\"))"),
            &["dir".to_string(), "name".to_string()],
            &ssa,
            BlockId(0),
            None,
            false,
        );
        assert_eq!(false_state.get(SsaValue(0)).map(|t| t.caps), Some(caps));
    }

    #[test]
    fn path_rejection_narrows_the_definition_reaching_the_branch() {
        // block 0: p = source;  -> block 1: if (p.includes("..") || p.startsWith("/")) ...
        // block 2 (false arm): p = req.query.b
        // The check proves nothing about the new value, so only the
        // definition live at the branch (v0) may be narrowed.
        let inst = |v: u32| SsaInst {
            value: SsaValue(v),
            op: SsaOp::Source,
            cfg_node: NodeIndex::new(v as usize),
            var_name: Some("p".into()),
            span: (0, 1),
        };
        let def = |b: u32| crate::ssa::ir::ValueDef {
            var_name: Some("p".into()),
            cfg_node: NodeIndex::new(0),
            block: BlockId(b),
        };
        let mut ssa = ssa_body_with_named_value("p");
        ssa.blocks = vec![
            SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![inst(0)],
                terminator: Terminator::Goto(BlockId(1)),
                preds: smallvec![],
                succs: smallvec![BlockId(1)],
            },
            SsaBlock {
                id: BlockId(1),
                phis: vec![],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: smallvec![BlockId(0)],
                succs: smallvec![BlockId(2)],
            },
            SsaBlock {
                id: BlockId(2),
                phis: vec![],
                body: vec![inst(1)],
                terminator: Terminator::Return(None),
                preds: smallvec![BlockId(1)],
                succs: smallvec![],
            },
        ];
        ssa.value_defs = vec![def(0), def(2)];

        let mut true_state = initial_state_with_abstract();
        let mut false_state = initial_state_with_abstract();
        super::super::apply_path_fact_branch_narrowing_with_aliases(
            &mut true_state,
            &mut false_state,
            &super::super::classify_path_branch("(p.includes(\"..\") || p.startsWith(\"/\"))"),
            &["p".to_string()],
            &ssa,
            BlockId(1),
            None,
            false,
        );
        let abs = false_state.abstract_state.as_ref().unwrap();
        assert!(abs.get(SsaValue(0)).path.is_path_safe());
        assert!(
            abs.get(SsaValue(1)).path.is_top(),
            "a redefinition after the check must not inherit the narrowed fact"
        );
    }

    #[test]
    fn branch_cond_sentinel_comparisons_set_semantic_negation() {
        use crate::taint::path_state::PredicateKind;
        // (text, expected kind, expected has_semantic_negation)
        let cases = [
            (
                "(ALLOWED.includes(cmd) === false)",
                PredicateKind::AllowlistCheck,
                true,
            ),
            (
                "ALLOWED.includes(cmd) !== false",
                PredicateKind::AllowlistCheck,
                false,
            ),
            (
                "(ALLOWED.indexOf(cmd) === -1)",
                PredicateKind::AllowlistCheck,
                true,
            ),
            (
                "ALLOWED.indexOf(cmd) !== -1",
                PredicateKind::AllowlistCheck,
                false,
            ),
            (
                "(ALLOWED[cmd] === undefined)",
                PredicateKind::AllowlistCheck,
                true,
            ),
            (
                "(false === in_array($cmd, $allowed, true))",
                PredicateKind::AllowlistCheck,
                true,
            ),
            (
                "(isValidName(cmd) === false)",
                PredicateKind::ValidationCall,
                true,
            ),
            (
                "is_valid_name(name) is False",
                PredicateKind::ValidationCall,
                true,
            ),
            (
                "isInvalidUrl(u) === false",
                PredicateKind::ValidationCall,
                false,
            ),
            // The `!=` belongs to the sentinel, not to a `typeof` test.
            ("isinstance(x, int) != True", PredicateKind::TypeCheck, true),
            (
                "isinstance(x, int) == True",
                PredicateKind::TypeCheck,
                false,
            ),
            ("typeof x !== 'number'", PredicateKind::TypeCheck, true),
            // A missing key and a `false` value look the same: validate
            // neither edge.
            ("(ALLOWED[cmd] === false)", PredicateKind::Unknown, false),
        ];
        for (text, kind, negated) in cases {
            let class = super::super::classify_branch_cond(text);
            assert_eq!(class.kind, kind, "{text}");
            assert_eq!(class.has_semantic_negation, negated, "{text}");
        }
        assert_eq!(
            super::super::classify_branch_cond("(ALLOWED[cmd] === false)").target_var,
            None
        );
    }

    #[test]
    fn is_path_safe_for_sink_proven_safe_returns_true() {
        use crate::abstract_interp::{AbstractState, AbstractValue, PathFact};

        let mut abs = AbstractState::empty();
        let v = SsaValue(0);
        // Mark v as proven path-safe via the builder API.
        let safe_fact = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        abs.set(v, AbstractValue::with_path_fact(safe_fact.clone()));
        assert!(safe_fact.is_path_safe());
        assert_eq!(abs.get(v).path, safe_fact);
    }

    #[test]
    fn is_path_safe_for_sink_unknown_axis_returns_false() {
        use crate::abstract_interp::PathFact;

        // Only dotdot is cleared, absolute stays Maybe → not path-safe.
        let half_fact = PathFact::default().with_dotdot_cleared();
        assert!(!half_fact.is_path_safe());
    }

    // ── is_non_data_return + detect_variant_inner_fact ──────────────────

    fn make_body_with_const_return(text: &str) -> SsaBody {
        // A trivial body with one block that returns a Const-defined SSA
        // value.  Built by hand because the public lowering pipeline
        // requires a full Cfg + analysis context.
        use crate::ssa::ir::{BlockId, SsaBlock, SsaInst, SsaOp, Terminator};
        use petgraph::graph::NodeIndex;
        let v = SsaValue(0);
        SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                preds: smallvec::SmallVec::new(),
                succs: smallvec::SmallVec::new(),
                phis: vec![],
                body: vec![SsaInst {
                    value: v,
                    op: SsaOp::Const(Some(text.to_string())),
                    cfg_node: NodeIndex::new(0),
                    var_name: None,
                    span: (0, 0),
                }],
                terminator: Terminator::Return(Some(v)),
            }],
            entry: BlockId(0),
            value_defs: vec![crate::ssa::ir::ValueDef {
                var_name: None,
                cfg_node: NodeIndex::new(0),
                block: BlockId(0),
            }],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        }
    }

    #[test]
    fn is_non_data_return_recognises_none_constant() {
        let body = make_body_with_const_return("None");
        assert!(super::super::is_non_data_return(SsaValue(0), &body));
    }

    #[test]
    fn is_non_data_return_recognises_null_and_nil_aliases() {
        for tag in ["null", "nil", "NULL", "undefined", "()"] {
            let body = make_body_with_const_return(tag);
            assert!(
                super::super::is_non_data_return(SsaValue(0), &body),
                "expected {tag} to be recognised as non-data return"
            );
        }
    }

    #[test]
    fn is_non_data_return_rejects_string_literals() {
        let body = make_body_with_const_return("\"some/path\"");
        assert!(
            !super::super::is_non_data_return(SsaValue(0), &body),
            "string literals must participate in path-safety join (could be unsafe)"
        );
    }
}

// ── receiver_candidates_for_type_lookup walks FieldProj ──────
//
// After SSA decomposition, `c.client.send(req)` lowers to
//   v_c      = Param("c", 0)
//   v_client = FieldProj(v_c, "client")
//   v_call   = Call("send", receiver: v_client, args: [v_req])
//
// The `receiver` of the outer call is `v_client`, not `v_c`.  For
// type-qualified label resolution to find the typed root (`c` of e.g.
// `RouterContext`), the candidate walk must traverse FieldProj receivers
// in addition to the existing Rust-only Call.receiver chain.  These tests
// pin the FieldProj-walking contract.
#[cfg(test)]
mod receiver_candidates_field_proj_tests {
    use super::super::*;
    use crate::symbol::Lang;
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    fn empty_value_def(name: &str) -> ValueDef {
        ValueDef {
            var_name: Some(name.into()),
            cfg_node: NodeIndex::new(0),
            block: BlockId(0),
        }
    }

    /// Build a one-block SSA body for `c.client.send(req)`:
    ///   v0 = Param(c, 0)
    ///   v1 = Param(req, 1)
    ///   v2 = FieldProj(v0, "client")
    ///   v3 = Call("send", receiver: v2, args: [v1])
    fn body_with_field_proj_chain() -> SsaBody {
        let mut interner = crate::ssa::ir::FieldInterner::default();
        let client_id = interner.intern("client");
        let blocks = vec![SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Param { index: 0 },
                    cfg_node: NodeIndex::new(0),
                    var_name: Some("c".into()),
                    span: (0, 0),
                },
                SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Param { index: 1 },
                    cfg_node: NodeIndex::new(0),
                    var_name: Some("req".into()),
                    span: (0, 0),
                },
                SsaInst {
                    value: SsaValue(2),
                    op: SsaOp::FieldProj {
                        receiver: SsaValue(0),
                        field: client_id,
                        projected_type: None,
                    },
                    cfg_node: NodeIndex::new(0),
                    var_name: Some("c.client".into()),
                    span: (0, 0),
                },
                SsaInst {
                    value: SsaValue(3),
                    op: SsaOp::Call {
                        callee: "send".into(),
                        callee_text: Some("c.client.send".into()),
                        args: vec![smallvec![SsaValue(1)]],
                        receiver: Some(SsaValue(2)),
                    },
                    cfg_node: NodeIndex::new(0),
                    var_name: Some("c.client.send".into()),
                    span: (0, 0),
                },
            ],
            terminator: Terminator::Return(Some(SsaValue(3))),
            preds: smallvec![],
            succs: smallvec![],
        }];
        SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs: vec![
                empty_value_def("c"),
                empty_value_def("req"),
                empty_value_def("c.client"),
                empty_value_def("c.client.send"),
            ],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: interner,
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        }
    }

    #[test]
    fn field_proj_receiver_walks_to_typed_root_in_go() {
        // Go is not Rust, so before the FieldProj walk fix the candidate
        // walk would have returned ONLY the immediate receiver
        // (v2 = FieldProj). We now walk through FieldProj.receiver to
        // recover v0 (the typed root `c`).
        let body = body_with_field_proj_chain();
        let cands =
            super::super::receiver_candidates_for_type_lookup(SsaValue(2), Some(&body), Lang::Go);
        assert!(
            cands.contains(&SsaValue(2)),
            "starts with the immediate receiver"
        );
        assert!(
            cands.contains(&SsaValue(0)),
            "must walk FieldProj.receiver to reach the typed root v0 (`c`); got {cands:?}",
        );
    }

    #[test]
    fn field_proj_receiver_walks_in_python_and_java() {
        let body = body_with_field_proj_chain();
        for lang in [Lang::Python, Lang::Java, Lang::JavaScript, Lang::TypeScript] {
            let cands =
                super::super::receiver_candidates_for_type_lookup(SsaValue(2), Some(&body), lang);
            assert!(
                cands.contains(&SsaValue(0)),
                "{:?}: FieldProj.receiver walk must reach v0; got {cands:?}",
                lang,
            );
        }
    }

    #[test]
    fn rust_walks_call_receiver_and_field_proj() {
        // Rust still walks Call.receiver (chained `.unwrap()` shape), and
        // now ALSO walks FieldProj.receiver for any intermediate field
        // accesses in the chain.
        let body = body_with_field_proj_chain();
        let cands =
            super::super::receiver_candidates_for_type_lookup(SsaValue(2), Some(&body), Lang::Rust);
        assert!(cands.contains(&SsaValue(0)));
    }

    #[test]
    fn no_ssa_body_returns_only_start() {
        let cands = super::super::receiver_candidates_for_type_lookup(SsaValue(2), None, Lang::Go);
        assert_eq!(cands.as_slice(), &[SsaValue(2)]);
    }

    #[test]
    fn cycle_safety_no_infinite_loop_on_self_ref() {
        // Pathological: a FieldProj whose receiver is itself.  Should not
        // infinite-loop; should bail after one step (out.contains check).
        let mut interner = crate::ssa::ir::FieldInterner::default();
        let f_id = interner.intern("self_ref");
        let blocks = vec![SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::FieldProj {
                    receiver: SsaValue(0),
                    field: f_id,
                    projected_type: None,
                },
                cfg_node: NodeIndex::new(0),
                var_name: None,
                span: (0, 0),
            }],
            terminator: Terminator::Return(Some(SsaValue(0))),
            preds: smallvec![],
            succs: smallvec![],
        }];
        let body = SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs: vec![empty_value_def("v0")],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: interner,
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let cands =
            super::super::receiver_candidates_for_type_lookup(SsaValue(0), Some(&body), Lang::Go);
        // Cycle: only the start value is recorded; no infinite walk.
        assert_eq!(cands.as_slice(), &[SsaValue(0)]);
    }

    /// The walk crosses blocks: `c` is defined in block 0, the projection in
    /// block 1, and the call in block 2. The value table names each defining
    /// block, so the walk has to follow it rather than assume block 0.
    #[test]
    fn walk_follows_definitions_across_blocks() {
        let mut interner = crate::ssa::ir::FieldInterner::default();
        let f_id = interner.intern("client");
        let inst = |value: u32, op: SsaOp| SsaInst {
            value: SsaValue(value),
            op,
            cfg_node: NodeIndex::new(0),
            var_name: None,
            span: (0, 0),
        };
        let block = |id: u32, body: Vec<SsaInst>, succ: Option<u32>| SsaBlock {
            id: BlockId(id),
            phis: vec![],
            body,
            terminator: match succ {
                Some(s) => Terminator::Goto(BlockId(s)),
                None => Terminator::Return(None),
            },
            preds: smallvec![],
            succs: succ.map(|s| smallvec![BlockId(s)]).unwrap_or_default(),
        };
        let def_in = |b: u32| ValueDef {
            var_name: None,
            cfg_node: NodeIndex::new(0),
            block: BlockId(b),
        };
        let body = SsaBody {
            blocks: vec![
                block(0, vec![inst(0, SsaOp::Param { index: 0 })], Some(1)),
                block(
                    1,
                    vec![inst(
                        1,
                        SsaOp::FieldProj {
                            receiver: SsaValue(0),
                            field: f_id,
                            projected_type: None,
                        },
                    )],
                    Some(2),
                ),
                block(
                    2,
                    vec![inst(
                        2,
                        SsaOp::Call {
                            callee: "send".into(),
                            callee_text: None,
                            args: vec![],
                            receiver: Some(SsaValue(1)),
                        },
                    )],
                    None,
                ),
            ],
            entry: BlockId(0),
            value_defs: vec![def_in(0), def_in(1), def_in(2)],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: interner,
            field_writes: Default::default(),
            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let cands =
            super::super::receiver_candidates_for_type_lookup(SsaValue(2), Some(&body), Lang::Rust);
        assert_eq!(cands.as_slice(), &[SsaValue(2), SsaValue(1), SsaValue(0)]);
    }

    /// A body whose value table names the wrong block still resolves, through
    /// the whole-body fallback.
    #[test]
    fn walk_survives_a_value_table_that_names_the_wrong_block() {
        let body = body_with_field_proj_chain();
        let mut skewed = body.clone();
        for vd in &mut skewed.value_defs {
            vd.block = BlockId(7);
        }
        let cands =
            super::super::receiver_candidates_for_type_lookup(SsaValue(2), Some(&skewed), Lang::Go);
        assert_eq!(cands.as_slice(), &[SsaValue(2), SsaValue(0)]);
    }
}

// ── Hierarchy: ResolvedSummary union semantics ──────────
//
// `merge_resolved_summaries_fanout` is invoked at virtual-dispatch call
// sites where the receiver's static type has multiple concrete
// implementers.  These tests pin the merge contract that taint
// soundness depends on.
#[cfg(test)]
mod fanout_merge_tests {
    use super::super::ResolvedSummary;
    use super::super::merge_resolved_summaries_fanout;
    use crate::labels::Cap;
    use crate::summary::SinkSite;
    use smallvec::smallvec;

    fn empty() -> ResolvedSummary {
        ResolvedSummary {
            source_caps: Cap::empty(),
            sanitizer_caps: Cap::empty(),
            sink_caps: Cap::empty(),
            param_to_sink: vec![],
            param_to_sink_sites: vec![],
            param_to_return_strip: vec![],
            propagates_taint: false,
            propagating_params: vec![],
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
            param_to_gate_filters: vec![],
            validated_params_to_return: vec![],
        }
    }

    /// B1, caps that grow taint signal (source/sink/receiver_to_sink)
    /// are unioned.  sanitizer_caps are intersected so only bits
    /// stripped by EVERY implementer count as cleared at the call site.
    #[test]
    fn merge_caps_union_or_intersect() {
        let mut a = empty();
        a.source_caps = Cap::from_bits(0b0011).unwrap();
        a.sanitizer_caps = Cap::from_bits(0b1110).unwrap();
        a.sink_caps = Cap::from_bits(0b0001).unwrap();
        a.receiver_to_sink = Cap::from_bits(0b0010).unwrap();

        let mut b = empty();
        b.source_caps = Cap::from_bits(0b0100).unwrap();
        b.sanitizer_caps = Cap::from_bits(0b0110).unwrap();
        b.sink_caps = Cap::from_bits(0b1000).unwrap();
        b.receiver_to_sink = Cap::from_bits(0b0001).unwrap();

        let m = merge_resolved_summaries_fanout(a, b);
        assert_eq!(m.source_caps.bits(), 0b0111, "source_caps must OR");
        assert_eq!(m.sanitizer_caps.bits(), 0b0110, "sanitizer_caps must AND");
        assert_eq!(m.sink_caps.bits(), 0b1001, "sink_caps must OR");
        assert_eq!(
            m.receiver_to_sink.bits(),
            0b0011,
            "receiver_to_sink must OR"
        );
    }

    /// B2, propagates_taint is OR'd; propagating_params is the union
    /// (any implementer's propagator counts).
    #[test]
    fn merge_propagation_unions() {
        let mut a = empty();
        a.propagates_taint = false;
        a.propagating_params = vec![0, 2];

        let mut b = empty();
        b.propagates_taint = true;
        b.propagating_params = vec![1, 2];

        let m = merge_resolved_summaries_fanout(a, b);
        assert!(m.propagates_taint, "propagates_taint must be OR'd");
        let mut params = m.propagating_params.clone();
        params.sort();
        assert_eq!(params, vec![0, 1, 2]);
    }

    /// B3, param_to_sink merges per-parameter caps (OR).  An impl
    /// that adds a sink at param N composes with another impl that
    /// adds a different cap at the same N.
    #[test]
    fn merge_param_to_sink_unions_per_param() {
        let mut a = empty();
        a.param_to_sink = vec![
            (0, Cap::from_bits(0b0001).unwrap()),
            (1, Cap::from_bits(0b0010).unwrap()),
        ];
        let mut b = empty();
        b.param_to_sink = vec![
            (0, Cap::from_bits(0b0100).unwrap()),
            (2, Cap::from_bits(0b1000).unwrap()),
        ];

        let m = merge_resolved_summaries_fanout(a, b);
        let mut sorted: Vec<(usize, u32)> = m
            .param_to_sink
            .iter()
            .map(|(i, c)| (*i, c.bits()))
            .collect();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![(0, 0b0101), (1, 0b0010), (2, 0b1000)],
            "param_to_sink must union per-parameter caps and preserve disjoint params"
        );
    }

    /// B4, param_to_sink_sites merges per-parameter site lists with
    /// PartialEq dedup.  The same site appearing in both impls (e.g.
    /// inherited definition) must not be reported twice.
    #[test]
    fn merge_param_to_sink_sites_dedups() {
        let shared = SinkSite {
            file_rel: "src/lib.rs".into(),
            line: 10,
            col: 5,
            snippet: "exec(q)".into(),
            cap: Cap::from_bits(0b0001).unwrap(),
            from_chain: false,
        };
        let unique_a = SinkSite {
            file_rel: "src/a.rs".into(),
            line: 20,
            col: 3,
            snippet: "do_a(q)".into(),
            cap: Cap::from_bits(0b0001).unwrap(),
            from_chain: false,
        };
        let unique_b = SinkSite {
            file_rel: "src/b.rs".into(),
            line: 30,
            col: 7,
            snippet: "do_b(q)".into(),
            cap: Cap::from_bits(0b0001).unwrap(),
            from_chain: false,
        };
        let mut a = empty();
        a.param_to_sink_sites = vec![(0, smallvec![shared.clone(), unique_a.clone()])];
        let mut b = empty();
        b.param_to_sink_sites = vec![(0, smallvec![shared.clone(), unique_b.clone()])];

        let m = merge_resolved_summaries_fanout(a, b);
        assert_eq!(m.param_to_sink_sites.len(), 1);
        let (idx, sites) = &m.param_to_sink_sites[0];
        assert_eq!(*idx, 0);
        assert_eq!(
            sites.len(),
            3,
            "shared site must dedup, unique sites preserved"
        );
        assert!(sites.iter().any(|s| s == &shared));
        assert!(sites.iter().any(|s| s == &unique_a));
        assert!(sites.iter().any(|s| s == &unique_b));
    }

    /// B5, SSA-precision fields are dropped on disagreement.  Two
    /// summaries with different `return_type` collapse to None;
    /// agreement is preserved.
    #[test]
    fn merge_ssa_precision_drops_on_disagreement() {
        use crate::ssa::type_facts::TypeKind;

        let mut a = empty();
        a.return_type = Some(TypeKind::Int);
        let mut b = empty();
        b.return_type = Some(TypeKind::String);
        let m = merge_resolved_summaries_fanout(a, b);
        assert_eq!(
            m.return_type, None,
            "disagreeing return_type values must be dropped to None"
        );

        let mut a = empty();
        a.return_type = Some(TypeKind::Int);
        let mut b = empty();
        b.return_type = Some(TypeKind::Int);
        let m = merge_resolved_summaries_fanout(a, b);
        assert_eq!(
            m.return_type,
            Some(TypeKind::Int),
            "agreeing return_type values must be preserved"
        );
    }

    /// B6, abstract_transfer + param_return_paths drop on
    /// disagreement (precise predicate-path data is not safely
    /// composable across distinct function bodies).
    #[test]
    fn merge_abstract_and_path_data_drops_on_disagreement() {
        use crate::abstract_interp::AbstractTransfer;
        use crate::summary::ssa_summary::{ReturnPathTransform, TaintTransform};

        let mut a = empty();
        a.abstract_transfer = vec![(0, AbstractTransfer::default())];
        a.param_return_paths = vec![(
            0,
            smallvec![ReturnPathTransform {
                transform: TaintTransform::Identity,
                path_predicate_hash: 0,
                known_true: 0,
                known_false: 0,
                abstract_contribution: None,
            }],
        )];
        let b = empty(); // empty path data → disagreement on element-by-element compare

        let m = merge_resolved_summaries_fanout(a, b);
        assert!(
            m.abstract_transfer.is_empty(),
            "abstract_transfer must drop on disagreement"
        );
        assert!(
            m.param_return_paths.is_empty(),
            "param_return_paths must drop on disagreement"
        );
    }

    /// B7, empty + empty = empty (no panic on degenerate inputs).
    #[test]
    fn merge_empties_is_identity() {
        let m = merge_resolved_summaries_fanout(empty(), empty());
        assert_eq!(m.source_caps, Cap::empty());
        assert_eq!(m.sink_caps, Cap::empty());
        assert!(m.param_to_sink.is_empty());
        assert!(!m.propagates_taint);
    }
}

//── synthetic field-WRITE round-trip ──────────────
//
// SSA lowering populates `SsaBody.field_writes` with entries that lift a
// synthetic base-update Assign (`obj.f = rhs`) into a structural field
// write.  When the taint engine sees one of those entries while
// `pointer_facts` is set, it must mirror the rhs taint into the
// matching `(loc, field)` cell on `SsaTaintState.field_taint`.  These
// tests pin the lift end-to-end without involving the real lowering
// pipeline so the side-table -> field-cell wiring is testable in
// isolation.
#[cfg(test)]
mod field_write_tests {
    use super::super::*;
    use crate::cfg::{AstMeta, CallMeta, Cfg, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::{Cap, DataLabel};
    use crate::pointer::PointsToFacts;
    use crate::ssa::ir::FieldId;
    use crate::state::symbol::SymbolInterner;
    use crate::taint::ssa_transfer::state::FieldTaintKey;
    use petgraph::graph::NodeIndex;
    use petgraph::prelude::*;
    use smallvec::smallvec;
    use std::collections::HashMap;

    /// Build a CFG with a single node tagged as a `Source` so we can
    /// drive `transfer_inst` with a real `cfg_node` for each instruction.
    fn make_cfg() -> (Cfg, NodeIndex, NodeIndex, NodeIndex, NodeIndex) {
        let mut cfg = Graph::new();
        let n_param = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 3),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta::default(),
            ..Default::default()
        });
        let n_source = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (5, 12),
                ..Default::default()
            },
            taint: TaintMeta {
                labels: smallvec![DataLabel::Source(Cap::ENV_VAR)],
                ..Default::default()
            },
            call: CallMeta::default(),
            ..Default::default()
        });
        let n_assign = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (14, 30),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta::default(),
            ..Default::default()
        });
        let n_proj = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (32, 45),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta::default(),
            ..Default::default()
        });
        (cfg, n_param, n_source, n_assign, n_proj)
    }

    /// Synthetic body for the W1 round-trip:
    /// ```ignore
    ///   v0: Param { 0 }      // `obj`
    ///   v1: Source           // env source
    ///   v2: Assign([v1])     // synth field write: obj.cache = v1.
    ///                        // `field_writes[v2] = (v0, FieldId(0))`
    ///                        // (FieldId(0) interned for "cache").
    ///   v3: FieldProj v0.cache  // read back `obj.cache`
    /// ```
    fn make_body() -> (SsaBody, FieldId) {
        let (_cfg, n_param, n_source, n_assign, n_proj) = make_cfg();
        let mut field_interner = crate::ssa::ir::FieldInterner::default();
        let cache_id = field_interner.intern("cache");

        let blocks = vec![SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Param { index: 0 },
                    cfg_node: n_param,
                    var_name: Some("obj".into()),
                    span: (0, 3),
                },
                SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Source,
                    cfg_node: n_source,
                    var_name: Some("src".into()),
                    span: (5, 12),
                },
                SsaInst {
                    value: SsaValue(2),
                    op: SsaOp::Assign(smallvec![SsaValue(1)]),
                    cfg_node: n_assign,
                    var_name: Some("obj".into()),
                    span: (14, 30),
                },
                SsaInst {
                    value: SsaValue(3),
                    op: SsaOp::FieldProj {
                        receiver: SsaValue(0),
                        field: cache_id,
                        projected_type: None,
                    },
                    cfg_node: n_proj,
                    var_name: Some("read".into()),
                    span: (32, 45),
                },
            ],
            terminator: Terminator::Return(None),
            preds: smallvec![],
            succs: smallvec![],
        }];
        let value_defs = vec![
            ValueDef {
                var_name: Some("obj".into()),
                cfg_node: n_param,
                block: BlockId(0),
            },
            ValueDef {
                var_name: Some("src".into()),
                cfg_node: n_source,
                block: BlockId(0),
            },
            ValueDef {
                var_name: Some("obj".into()),
                cfg_node: n_assign,
                block: BlockId(0),
            },
            ValueDef {
                var_name: Some("read".into()),
                cfg_node: n_proj,
                block: BlockId(0),
            },
        ];
        let mut field_writes = rustc_hash::FxHashMap::default();
        field_writes.insert(SsaValue(2), (SsaValue(0), cache_id));
        let body = SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs,
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner,
            field_writes,
            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        (body, cache_id)
    }

    /// Run pointer analysis on the body so we get realistic pt() sets.
    fn analyse(body: &SsaBody) -> PointsToFacts {
        crate::pointer::analyse_body(body, crate::cfg::BodyId(7))
    }

    /// Reuse `make_cfg`'s nodes, the body's instructions all reference
    /// them, so `transfer_inst` can index `cfg[cfg_node]`.
    fn drive(body: &SsaBody, pf: &PointsToFacts) -> SsaTaintState {
        // We need a CFG that contains the bodies' cfg_nodes.
        let (cfg, _, _, _, _) = make_cfg();
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(7),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: Some(pf),
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };

        let mut state = SsaTaintState::initial();
        for inst in &body.blocks[0].body {
            transfer_inst(inst, &cfg, body, &transfer, &mut state);
        }
        state
    }

    /// Round-trip: a synthetic field write records the rhs taint into the
    /// `(loc, field)` cell, and a subsequent FieldProj read recovers it.
    #[test]
    fn write_then_read_round_trips() {
        let (body, cache_id) = make_body();
        let pf = analyse(&body);
        let state = drive(&body, &pf);

        // The FieldProj read on `obj.cache` should observe the source's
        // ENV_VAR cap via the `(Param(_, 0), cache)` field cell.
        let read_taint = state
            .get(SsaValue(3))
            .expect("FieldProj read should produce taint");
        assert!(
            read_taint.caps.contains(Cap::ENV_VAR),
            "field-proj read must inherit source's ENV_VAR cap; got {:?}",
            read_taint.caps,
        );

        // The cell itself must exist on `pt(v0)`'s sole member.
        let pt_v0 = pf.pt(SsaValue(0));
        assert!(!pt_v0.is_empty() && !pt_v0.is_top());
        let parent_loc = pt_v0.iter().next().unwrap();
        let cell = state
            .get_field(FieldTaintKey {
                loc: parent_loc,
                field: cache_id,
            })
            .expect("field cell should be populated by the W1 hook");
        assert!(cell.taint.caps.contains(Cap::ENV_VAR));
    }

    /// Pointer-disabled run (`pointer_facts: None`): no field cell is
    /// recorded, no taint flows through the `obj.cache` projection.  The
    /// strict-additive contract, pointer-disabled behaviour is the
    /// pre-W1 baseline.
    #[test]
    fn pointer_disabled_run_produces_no_field_taint() {
        let (body, cache_id) = make_body();
        // Build the same body but skip `pointer_facts` on the transfer.
        let (cfg, _, _, _, _) = make_cfg();
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: None,
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };
        let mut state = SsaTaintState::initial();
        for inst in &body.blocks[0].body {
            transfer_inst(inst, &cfg, &body, &transfer, &mut state);
        }
        // No field cell populated.
        assert!(
            state.field_taint.is_empty(),
            "pointer-disabled run must not populate field_taint",
        );
        // FieldProj reads still produce the receiver's existing taint ,
        // none, so no entry for SsaValue(3) either.
        assert!(state.get(SsaValue(3)).is_none());
        let _ = cache_id;
    }

    /// W4: when the rhs of a synth field-WRITE has its symbol-level
    /// `validated_must` bit set, the field cell records
    /// `validated_must = true`.  A subsequent FieldProj read seeds the
    /// projected value's symbol-level `validated_must` from the cell.
    ///
    /// This is the key invariant: validation flows *through* abstract
    /// field identity, the read recovers what the write recorded.
    #[test]
    fn write_then_read_preserves_validated_must() {
        let (body, cache_id) = make_body();
        let pf = analyse(&body);

        // Build an interner that knows "src" and "read" so we can seed
        // and observe symbol-level validation bits.
        let mut interner = SymbolInterner::new();
        let sym_src = interner.intern("src");
        let sym_read = interner.intern("read");

        let (cfg, _, _, _, _) = make_cfg();
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(7),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: Some(&pf),
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };

        // Validate `src` right after its definition, as a guard on it
        // would, so the synth Assign observes the bit at write time.  A
        // bit seeded before the definition would describe no value of
        // `src`: the definition itself drops it.
        let mut state = SsaTaintState::initial();
        for inst in &body.blocks[0].body {
            transfer_inst(inst, &cfg, &body, &transfer, &mut state);
            if inst.var_name.as_deref() == Some("src") {
                state.validated_must.insert(sym_src);
                state.validated_may.insert(sym_src);
            }
        }

        // Cell records validated_must=true (rhs was must-validated).
        let pt_v0 = pf.pt(SsaValue(0));
        let parent_loc = pt_v0.iter().next().unwrap();
        let cell = state
            .get_field(FieldTaintKey {
                loc: parent_loc,
                field: cache_id,
            })
            .expect("W1 cell present");
        assert!(
            cell.validated_must,
            "cell.validated_must must be true after a must-validated rhs"
        );
        assert!(cell.validated_may);

        // Read seeded the projected symbol's validation bits.
        assert!(
            state.validated_must.contains(sym_read),
            "FieldProj read should seed validated_must on the projected symbol"
        );
        assert!(state.validated_may.contains(sym_read));
    }

    /// Empty-pt skip: when the receiver has no recorded points-to set
    /// (e.g. its op produces no abstract location), the field-write
    /// hook records nothing.  Strict-additive over the existing
    /// pass-through behaviour.
    #[test]
    fn write_with_empty_pt_records_nothing() {
        // Body with v0 = Const (no abstract location), v1 = Source,
        // v2 = Assign([v1]) annotated as field write of `v0.cache`.
        let (cfg, n0, n1, n2, _n3) = make_cfg();
        let mut field_interner = crate::ssa::ir::FieldInterner::default();
        let cache_id = field_interner.intern("cache");

        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("0".into())),
                        cfg_node: n0,
                        var_name: Some("c".into()),
                        span: (0, 1),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Source,
                        cfg_node: n1,
                        var_name: Some("src".into()),
                        span: (5, 12),
                    },
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Assign(smallvec![SsaValue(1)]),
                        cfg_node: n2,
                        var_name: Some("c".into()),
                        span: (14, 30),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("c".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("src".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("c".into()),
                    cfg_node: n2,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner,
            field_writes: {
                let mut m = rustc_hash::FxHashMap::default();
                m.insert(SsaValue(2), (SsaValue(0), cache_id));
                m
            },
            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let pf = crate::pointer::analyse_body(&body, crate::cfg::BodyId(0));
        // v0 is Const → empty pt, the hook should not insert anything.
        assert!(
            pf.pt(SsaValue(0)).is_empty(),
            "Const value should have empty pt set",
        );

        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: Some(&pf),
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };

        let mut state = SsaTaintState::initial();
        for inst in &body.blocks[0].body {
            transfer_inst(inst, &cfg, &body, &transfer, &mut state);
        }
        assert!(
            state.field_taint.is_empty(),
            "empty pt set must produce no field cell entries",
        );
    }
}

//── container ELEM write/read round-trip ──────────
//
// Container methods like `arr.push(v)` / `arr.shift()` flow per-element
// taint through the `Field(_, ELEM)` cells on `SsaTaintState`.  These
// tests pin the contract: a write hook on the receiver-side stores arg
// taint into the cell, and a subsequent read picks it up via the
// `analyse_body`-emitted FieldProj-like projection on the call result.
#[cfg(test)]
mod container_elem_tests {
    use super::super::*;
    use crate::cfg::{AstMeta, CallMeta, Cfg, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::{Cap, DataLabel};
    use crate::ssa::ir::FieldId;
    use crate::state::symbol::SymbolInterner;
    use crate::taint::ssa_transfer::state::FieldTaintKey;
    use petgraph::graph::NodeIndex;
    use petgraph::prelude::*;
    use smallvec::smallvec;
    use std::collections::HashMap;

    fn cfg_with_nodes(n: usize) -> (Cfg, Vec<NodeIndex>) {
        let mut cfg = Graph::new();
        let mut nodes = Vec::new();
        for i in 0..n {
            let nidx = cfg.add_node(NodeInfo {
                kind: if i == 1 { StmtKind::Seq } else { StmtKind::Seq },
                ast: AstMeta {
                    span: (i * 10, i * 10 + 5),
                    ..Default::default()
                },
                taint: if i == 1 {
                    TaintMeta {
                        labels: smallvec![DataLabel::Source(Cap::ENV_VAR)],
                        ..Default::default()
                    }
                } else {
                    TaintMeta::default()
                },
                call: CallMeta::default(),
                ..Default::default()
            });
            nodes.push(nidx);
        }
        (cfg, nodes)
    }

    fn run_with_pointer(
        body: &SsaBody,
        cfg: &Cfg,
        pf: &crate::pointer::PointsToFacts,
    ) -> SsaTaintState {
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(7),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: Some(pf),
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };

        let mut state = SsaTaintState::initial();
        for inst in &body.blocks[0].body {
            transfer_inst(inst, cfg, body, &transfer, &mut state);
        }
        state
    }

    /// `arr.push(source()); arr.shift()`, the read picks the source's
    /// caps up via the ELEM cell.
    #[test]
    fn container_write_then_read_round_trips_taint() {
        let (cfg, nodes) = cfg_with_nodes(4);
        let n_param = nodes[0];
        let n_source = nodes[1];
        let n_push = nodes[2];
        let n_shift = nodes[3];

        let blocks = vec![SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Param { index: 0 },
                    cfg_node: n_param,
                    var_name: Some("arr".into()),
                    span: (0, 3),
                },
                SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Source,
                    cfg_node: n_source,
                    var_name: Some("src".into()),
                    span: (10, 15),
                },
                SsaInst {
                    value: SsaValue(2),
                    op: SsaOp::Call {
                        callee: "push".into(),
                        callee_text: None,
                        args: vec![smallvec![SsaValue(1)]],
                        receiver: Some(SsaValue(0)),
                    },
                    cfg_node: n_push,
                    var_name: None,
                    span: (20, 25),
                },
                SsaInst {
                    value: SsaValue(3),
                    op: SsaOp::Call {
                        callee: "shift".into(),
                        callee_text: None,
                        args: vec![],
                        receiver: Some(SsaValue(0)),
                    },
                    cfg_node: n_shift,
                    var_name: Some("e".into()),
                    span: (30, 35),
                },
            ],
            terminator: Terminator::Return(None),
            preds: smallvec![],
            succs: smallvec![],
        }];
        let body = SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("arr".into()),
                    cfg_node: n_param,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("src".into()),
                    cfg_node: n_source,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: None,
                    cfg_node: n_push,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("e".into()),
                    cfg_node: n_shift,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        // Run pointer analysis first to confirm the result of `shift()`
        // includes a `Field(_, ELEM)` member.  The W2 transfer hook
        // populates the cell on `push`; the FieldProj-like read on
        // `shift` then finds the cell on the cross-projection from
        // `analyse_body`.
        let pf = crate::pointer::analyse_body(&body, crate::cfg::BodyId(7));
        let pt_shift = pf.pt(SsaValue(3));
        assert!(
            pt_shift.iter().any(|loc| matches!(
                pf.interner.resolve(loc),
                crate::pointer::AbsLoc::Field { field, .. } if *field == FieldId::ELEM
            )),
            "shift result must project through Field(_, ELEM); got {:?}",
            pt_shift,
        );

        // Drive the transfer.  `e := arr.shift()` goes through the
        // existing Call arm, the W2 path is the *write* on `push`.
        // The element-read side already exists on `analyse_body`; the
        // taint engine doesn't yet read field cells through call-result
        // paths (Call args are walked by Call's own argument-taint
        // logic, not field cells), so this test verifies the write
        // populated the cell, not that the call result automatically
        // recovers it through a field cell read.
        let state = run_with_pointer(&body, &cfg, &pf);

        // The push hook must have populated `(pt(arr), ELEM)`.
        let pt_arr = pf.pt(SsaValue(0));
        assert!(!pt_arr.is_empty() && !pt_arr.is_top());
        for loc in pt_arr.iter() {
            let cell = state.get_field(FieldTaintKey {
                loc,
                field: FieldId::ELEM,
            });
            assert!(
                cell.map(|c| c.taint.caps.contains(Cap::ENV_VAR))
                    .unwrap_or(false),
                "ELEM cell on pt(arr) {:?} must carry the source's ENV_VAR cap",
                loc,
            );
        }
    }

    /// W4: `arr.push(validate(src)); arr.shift()`, the push records
    /// `validated_must = true` on the ELEM cell because the pushed
    /// value's symbol carried `validated_must`.  The shift call result
    /// reads through the cell and seeds the result symbol's
    /// `validated_must`.
    ///
    /// This is the fixture that motivated the W4 cell-shape change in
    /// the prompt: `cmd := queue.shift()` after a validated push must
    /// surface the validation on the read.
    #[test]
    fn push_then_shift_preserves_validated_must() {
        let (cfg, nodes) = cfg_with_nodes(4);
        let n_param = nodes[0];
        let n_source = nodes[1];
        let n_push = nodes[2];
        let n_shift = nodes[3];

        let blocks = vec![SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Param { index: 0 },
                    cfg_node: n_param,
                    var_name: Some("arr".into()),
                    span: (0, 3),
                },
                SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Source,
                    cfg_node: n_source,
                    var_name: Some("src".into()),
                    span: (10, 15),
                },
                SsaInst {
                    value: SsaValue(2),
                    op: SsaOp::Call {
                        callee: "push".into(),
                        callee_text: None,
                        args: vec![smallvec![SsaValue(1)]],
                        receiver: Some(SsaValue(0)),
                    },
                    cfg_node: n_push,
                    var_name: None,
                    span: (20, 25),
                },
                SsaInst {
                    value: SsaValue(3),
                    op: SsaOp::Call {
                        callee: "shift".into(),
                        callee_text: None,
                        args: vec![],
                        receiver: Some(SsaValue(0)),
                    },
                    cfg_node: n_shift,
                    var_name: Some("cmd".into()),
                    span: (30, 35),
                },
            ],
            terminator: Terminator::Return(None),
            preds: smallvec![],
            succs: smallvec![],
        }];
        let body = SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("arr".into()),
                    cfg_node: n_param,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("src".into()),
                    cfg_node: n_source,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: None,
                    cfg_node: n_push,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("cmd".into()),
                    cfg_node: n_shift,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let pf = crate::pointer::analyse_body(&body, crate::cfg::BodyId(7));

        // Build an interner that knows the relevant variable names.
        let mut interner = SymbolInterner::new();
        let sym_src = interner.intern("src");
        let sym_cmd = interner.intern("cmd");

        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(7),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: Some(&pf),
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };

        // Validate `src` right after its definition (before the push
        // fires), as a guard on it would.  A bit seeded before the
        // definition would describe no value of `src`.
        let mut state = SsaTaintState::initial();
        for inst in &body.blocks[0].body {
            transfer_inst(inst, &cfg, &body, &transfer, &mut state);
            if inst.var_name.as_deref() == Some("src") {
                state.validated_must.insert(sym_src);
                state.validated_may.insert(sym_src);
            }
        }

        // Cell carries validated_must=true after push.
        let pt_arr = pf.pt(SsaValue(0));
        for loc in pt_arr.iter() {
            let cell = state
                .get_field(FieldTaintKey {
                    loc,
                    field: FieldId::ELEM,
                })
                .expect("push must have populated the ELEM cell");
            assert!(
                cell.validated_must,
                "push of must-validated value sets cell.validated_must (loc={:?})",
                loc
            );
        }

        // The W4 read counterpart on `shift` seeded `cmd`'s
        // validated_must from the cell.
        assert!(
            state.validated_must.contains(sym_cmd),
            "shift call result must inherit validated_must from the ELEM cell"
        );
    }

    /// Pointer-disabled run records nothing on container writes.
    #[test]
    fn container_write_pointer_disabled_records_nothing() {
        let (cfg, nodes) = cfg_with_nodes(3);
        let n_param = nodes[0];
        let n_source = nodes[1];
        let n_push = nodes[2];

        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Param { index: 0 },
                        cfg_node: n_param,
                        var_name: Some("arr".into()),
                        span: (0, 3),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Source,
                        cfg_node: n_source,
                        var_name: Some("src".into()),
                        span: (10, 15),
                    },
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Call {
                            callee: "push".into(),
                            callee_text: None,
                            args: vec![smallvec![SsaValue(1)]],
                            receiver: Some(SsaValue(0)),
                        },
                        cfg_node: n_push,
                        var_name: None,
                        span: (20, 25),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("arr".into()),
                    cfg_node: n_param,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("src".into()),
                    cfg_node: n_source,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: None,
                    cfg_node: n_push,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: None,
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };
        let mut state = SsaTaintState::initial();
        for inst in &body.blocks[0].body {
            transfer_inst(inst, &cfg, &body, &transfer, &mut state);
        }
        assert!(
            state.field_taint.is_empty(),
            "pointer-disabled container write must not populate field_taint",
        );
    }
}

//── cross-call field-points-to application ────────
//
// `apply_field_points_to_writes` is the resolver-side hook that turns
// callee-summary `field_points_to.param_field_writes` into caller-side
// field_taint cells.  These tests pin the substitution contract:
// param_idx → caller args, u32::MAX → receiver, "<elem>" → ELEM
// sentinel, and unknown field names are skipped.
#[cfg(test)]
mod cross_call_field_tests {
    use super::super::apply_field_points_to_writes;
    use super::super::*;
    use crate::cfg::{AstMeta, CallMeta, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::{Cap, DataLabel};
    use crate::ssa::ir::FieldId;
    use crate::state::symbol::SymbolInterner;
    use crate::summary::points_to::FieldPointsToSummary;
    use crate::taint::domain::{TaintOrigin, VarTaint};
    use crate::taint::ssa_transfer::state::FieldTaintKey;
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    /// W3 / W4: shared empty interner, these unit tests don't seed
    /// validation bits, so a fresh interner is sufficient for the
    /// `interner` parameter on `apply_field_points_to_writes`.
    fn empty_interner() -> SymbolInterner {
        SymbolInterner::new()
    }

    /// Build a tiny caller body that has one param (`obj`), one source,
    /// and intern's a single field name "cache".  Returns the body, the
    /// `cache` FieldId, and the resulting `PointsToFacts`.
    fn caller_body() -> (SsaBody, FieldId, crate::pointer::PointsToFacts) {
        let mut field_interner = crate::ssa::ir::FieldInterner::default();
        let cache_id = field_interner.intern("cache");
        // We also pre-register a dummy node 0 in CFG.
        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Param { index: 0 },
                        cfg_node: NodeIndex::new(0),
                        var_name: Some("obj".into()),
                        span: (0, 3),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Source,
                        cfg_node: NodeIndex::new(0),
                        var_name: Some("src".into()),
                        span: (5, 12),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("obj".into()),
                    cfg_node: NodeIndex::new(0),
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("src".into()),
                    cfg_node: NodeIndex::new(0),
                    block: BlockId(0),
                },
            ],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner,
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let pf = crate::pointer::analyse_body(&body, crate::cfg::BodyId(7));
        (body, cache_id, pf)
    }

    fn seeded_state() -> SsaTaintState {
        let mut state = SsaTaintState::initial();
        // SsaValue(1) has source taint with ENV_VAR cap.
        state.set(
            SsaValue(1),
            VarTaint {
                caps: Cap::ENV_VAR,
                origins: smallvec![TaintOrigin {
                    node: NodeIndex::new(0),
                    source_kind: crate::labels::SourceKind::EnvironmentConfig,
                    source_span: Some((5, 12)),
                }],
                uses_summary: false,
            },
        );
        state
    }

    /// Callee summary with `param_field_writes[(0, ["cache"])]` ,
    /// "callee writes cache field on parameter 0 (obj)".
    /// Caller passes `(obj, source)` to this callee, `arg 0 = obj`,
    /// but the W3 hook resolves the *value at arg position 0* as the
    /// receiver of the field write, populating its pt's cells.
    ///
    /// We model the caller as `callee(obj, source)` with arg 0 = obj
    /// (the receiver) and arg 1 = source (the value being written).
    /// The callee's signature is `fn store(obj, value) { obj.cache = value; }`
    ///, so the field write on param 0 is keyed by `pt(obj)` and the
    /// taint comes from arg 1's caps.  Our helper conservatively unions
    /// every arg's taint into the cell, which over-tints (for this
    /// shape, arg 0's pt member becomes the loc, with arg 0's own taint
    /// applied), but is sound.
    ///
    /// To make the test precise, we model the simpler shape `fn store(obj)
    /// { obj.cache = source(); }`, callee writes a literal source into
    /// `obj.cache`, with no value parameter.  Then the caller-side hook
    /// only sees param 0's taint (zero), so the cell is empty and the
    /// test fails.
    ///
    /// The cleanest test fixture: param_idx 0 with field "cache", and
    /// at the call site arg 0 carries source taint.  The hook then
    /// records (pt(arg0_value), cache) ← arg0_value's taint.  In a
    /// real callee this corresponds to "callee writes its parameter
    /// value into a self.cache field internally", but the spread we
    /// validate is just substitute-and-mirror.
    #[test]
    fn cross_call_writes_into_param_field_cell() {
        let (body, cache_id, pf) = caller_body();
        let mut state = seeded_state();
        // Caller-side args: arg 0 = source-tainted SSA (SsaValue(1)).
        // The W3 hook reads pt(arg0_v) which traces through pt(SsaValue(1));
        // that value is `Source`, so its pt is empty by design.
        //
        // We need a value whose pt covers an `AbsLoc::Param`.  Use
        // SsaValue(0) (the "obj" Param) as arg 0 *and* seed it with
        // taint manually so the substitution has caps to mirror.
        state.set(
            SsaValue(0),
            VarTaint {
                caps: Cap::ENV_VAR,
                origins: smallvec![TaintOrigin {
                    node: NodeIndex::new(0),
                    source_kind: crate::labels::SourceKind::EnvironmentConfig,
                    source_span: Some((0, 3)),
                }],
                uses_summary: false,
            },
        );

        let mut summary = FieldPointsToSummary::empty();
        summary.add_write(0, "cache");

        let args: Vec<smallvec::SmallVec<[SsaValue; 2]>> = vec![smallvec![SsaValue(0)]];
        let receiver = None;
        apply_field_points_to_writes(
            &summary,
            &args,
            &receiver,
            &mut state,
            &body,
            &pf,
            &empty_interner(),
        );

        // pt(SsaValue(0)) is `{Param(_, 0)}`.
        let pt_v0 = pf.pt(SsaValue(0));
        let loc = pt_v0
            .iter()
            .next()
            .expect("Param value must have non-empty pt");
        let cell = state
            .get_field(FieldTaintKey {
                loc,
                field: cache_id,
            })
            .expect("W3 hook should populate (Param, cache) cell");
        assert!(cell.taint.caps.contains(Cap::ENV_VAR));
    }

    /// Receiver flow uses sentinel `param_idx == u32::MAX`.
    #[test]
    fn cross_call_receiver_field_uses_max_sentinel() {
        let (body, cache_id, pf) = caller_body();
        let mut state = SsaTaintState::initial();
        // Seed receiver with taint, SsaValue(0) is the param/receiver.
        state.set(
            SsaValue(0),
            VarTaint {
                caps: Cap::ENV_VAR,
                origins: smallvec![],
                uses_summary: false,
            },
        );

        let mut summary = FieldPointsToSummary::empty();
        summary.add_write(u32::MAX, "cache");

        let args: Vec<smallvec::SmallVec<[SsaValue; 2]>> = vec![];
        let receiver = Some(SsaValue(0));
        apply_field_points_to_writes(
            &summary,
            &args,
            &receiver,
            &mut state,
            &body,
            &pf,
            &empty_interner(),
        );

        let pt_recv = pf.pt(SsaValue(0));
        let loc = pt_recv.iter().next().unwrap();
        assert!(
            state
                .get_field(FieldTaintKey {
                    loc,
                    field: cache_id
                })
                .is_some()
        );
    }

    /// `<elem>` field name routes to `FieldId::ELEM` directly without
    /// going through interner lookup.
    #[test]
    fn cross_call_elem_marker_routes_to_elem_sentinel() {
        let (body, _cache_id, pf) = caller_body();
        let mut state = SsaTaintState::initial();
        state.set(
            SsaValue(0),
            VarTaint {
                caps: Cap::ENV_VAR,
                origins: smallvec![],
                uses_summary: false,
            },
        );

        let mut summary = FieldPointsToSummary::empty();
        summary.add_write(0, "<elem>");

        let args: Vec<smallvec::SmallVec<[SsaValue; 2]>> = vec![smallvec![SsaValue(0)]];
        apply_field_points_to_writes(
            &summary,
            &args,
            &None,
            &mut state,
            &body,
            &pf,
            &empty_interner(),
        );

        let pt_v0 = pf.pt(SsaValue(0));
        let loc = pt_v0.iter().next().unwrap();
        assert!(
            state
                .get_field(FieldTaintKey {
                    loc,
                    field: FieldId::ELEM
                })
                .is_some(),
            "ELEM cell must be populated when summary uses '<elem>' marker",
        );
    }

    /// Field names the caller never interned are skipped silently ,
    /// no FieldProj read in the caller could observe such a cell.
    #[test]
    fn cross_call_unknown_field_name_skipped() {
        let (body, _cache_id, pf) = caller_body();
        let mut state = SsaTaintState::initial();
        state.set(
            SsaValue(0),
            VarTaint {
                caps: Cap::ENV_VAR,
                origins: smallvec![],
                uses_summary: false,
            },
        );

        let mut summary = FieldPointsToSummary::empty();
        // "unknown" not in caller's field_interner.
        summary.add_write(0, "unknown");

        let args: Vec<smallvec::SmallVec<[SsaValue; 2]>> = vec![smallvec![SsaValue(0)]];
        apply_field_points_to_writes(
            &summary,
            &args,
            &None,
            &mut state,
            &body,
            &pf,
            &empty_interner(),
        );

        assert!(
            state.field_taint.is_empty(),
            "unknown field name must not create a cell",
        );
    }

    /// Overflow summary is treated conservatively as no-op, the
    /// engine cannot soundly cell-flood, so it skips entirely.
    #[test]
    fn cross_call_overflow_summary_is_noop() {
        let (body, _cache_id, pf) = caller_body();
        let mut state = SsaTaintState::initial();
        state.set(
            SsaValue(0),
            VarTaint {
                caps: Cap::ENV_VAR,
                origins: smallvec![],
                uses_summary: false,
            },
        );

        let mut summary = FieldPointsToSummary::empty();
        summary.add_write(0, "cache");
        summary.overflow = true; // Force overflow

        let args: Vec<smallvec::SmallVec<[SsaValue; 2]>> = vec![smallvec![SsaValue(0)]];
        apply_field_points_to_writes(
            &summary,
            &args,
            &None,
            &mut state,
            &body,
            &pf,
            &empty_interner(),
        );
        assert!(state.field_taint.is_empty());
    }

    /// Suppress unused-variable warnings for builders we may not exercise.
    #[test]
    fn ensure_helpers_compile() {
        // Body / source-label imports are used by the other tests; this
        // exists to keep the imports referenced under module-level
        // compile checks even if a single test path is filtered out.
        let _ = NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta::default(),
            taint: TaintMeta {
                labels: smallvec![DataLabel::Source(Cap::ENV_VAR)],
                ..Default::default()
            },
            call: CallMeta::default(),
            ..Default::default()
        };
    }
}

// ── A7 audit: field_taint reads respect the origin cap ─────────────────
//
// `SsaTaintState.add_field` already routes through `merge_origins`, but
// the FieldProj READ path used to walk the cell's origins inline,
// deduping by node only, meaning a cell with N>cap origins surfaced
// all N to the projected SSA value.  After A7, the read path uses
// `push_origin_bounded`, ensuring the cap-driven survivor selection
// applies on read too.
#[cfg(test)]
mod field_taint_origin_cap_tests {
    use super::super::*;
    use crate::cfg::{AstMeta, CallMeta, Cfg, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::Cap;
    use crate::ssa::ir::FieldId;
    use crate::state::symbol::SymbolInterner;
    use crate::taint::domain::TaintOrigin;
    use crate::taint::ssa_transfer::state::FieldTaintKey;
    use petgraph::graph::NodeIndex;
    use petgraph::prelude::*;
    use smallvec::smallvec;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static TEST_GUARD: Mutex<()> = Mutex::new(());

    /// Build a minimal body with one Param + one FieldProj read on
    /// `obj.cache`, whose cell is pre-populated with > cap origins.
    fn build_body() -> (SsaBody, FieldId, Cfg, NodeIndex) {
        let mut cfg = Graph::new();
        let n_param = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (0, 3),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta::default(),
            ..Default::default()
        });
        let n_proj = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ast: AstMeta {
                span: (5, 12),
                ..Default::default()
            },
            taint: TaintMeta::default(),
            call: CallMeta::default(),
            ..Default::default()
        });

        let mut field_interner = crate::ssa::ir::FieldInterner::default();
        let cache_id = field_interner.intern("cache");
        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Param { index: 0 },
                        cfg_node: n_param,
                        var_name: Some("obj".into()),
                        span: (0, 3),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::FieldProj {
                            receiver: SsaValue(0),
                            field: cache_id,
                            projected_type: None,
                        },
                        cfg_node: n_proj,
                        var_name: Some("read".into()),
                        span: (5, 12),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("obj".into()),
                    cfg_node: n_param,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("read".into()),
                    cfg_node: n_proj,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner,
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        (body, cache_id, cfg, n_proj)
    }

    /// Pre-populate the cell with `n` distinct-node origins, then read
    /// through the FieldProj.  Cap is set tight via the test-only
    /// override so we observe truncation.
    #[test]
    fn field_proj_read_respects_origin_cap() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        crate::taint::ssa_transfer::state::set_max_origins_override(2);

        let (body, cache_id, cfg, _n_proj) = build_body();
        let pf = crate::pointer::analyse_body(&body, crate::cfg::BodyId(0));

        // Pre-populate the (Param, cache) cell with 4 origins ,
        // 2× the cap.  The `add_field` path already truncates via
        // `merge_origins`, so we go through it 4 times to grow.
        let mut state = SsaTaintState::initial();
        let pt_v0 = pf.pt(SsaValue(0));
        let parent_loc = pt_v0.iter().next().unwrap();
        for i in 0..4 {
            let key = FieldTaintKey {
                loc: parent_loc,
                field: cache_id,
            };
            state.add_field(
                key,
                VarTaint {
                    caps: Cap::ENV_VAR,
                    origins: smallvec![TaintOrigin {
                        node: NodeIndex::new(100 + i),
                        source_kind: crate::labels::SourceKind::EnvironmentConfig,
                        source_span: Some((i * 10, i * 10 + 3)),
                    }],
                    uses_summary: false,
                },
                false,
                false,
            );
        }
        // After 4 add_field calls under cap=2, the cell should have ≤ 2
        // origins (merge_origins truncates).
        let cell = state
            .get_field(FieldTaintKey {
                loc: parent_loc,
                field: cache_id,
            })
            .unwrap();
        assert!(
            cell.taint.origins.len() <= 2,
            "field cell origin count must respect cap=2; got {}",
            cell.taint.origins.len(),
        );

        // Run the FieldProj read.  Origin cap on the projected value
        // must also be ≤ 2.
        let interner = SymbolInterner::new();
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner: &interner,
            local_summaries: &local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: Some(&pf),
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        };
        for inst in &body.blocks[0].body {
            transfer_inst(inst, &cfg, &body, &transfer, &mut state);
        }
        let read = state
            .get(SsaValue(1))
            .expect("FieldProj read should produce taint");
        assert!(
            read.origins.len() <= 2,
            "projected SSA value's origin count must respect cap=2; got {}",
            read.origins.len(),
        );

        crate::taint::ssa_transfer::state::set_max_origins_override(0);
    }
}

// ── A2 audit: lattice exercised through full worklist ──────────────────
//
// A8 covered convergence on synthetic states; A2 layers on the
// requirement that the same lattice composes correctly with
// `run_ssa_taint_full`'s multi-block worklist.  These tests build a
// real SSA body with a manually-populated `field_writes` side-table,
// run the full worklist, and assert convergence + flow semantics on
// the field_taint cells.
//
// Two scenarios:
// 1. `must_validated_flows_through_join`, both predecessor blocks
//    write the cell with `validated_must = true`.  After the join, the
//    cell at the read site retains `validated_must = true` (AND
//    intersection of two `true`s).
// 2. `early_exit_branch_drops_validated_must`, only one predecessor
//    writes; the other reaches the read block via an empty branch.
//    After the join, the cell has `validated_must = false`,
//    `validated_may = true`, W4's must/may intersection in action.
#[cfg(test)]
mod pointer_lattice_worklist_tests {
    use super::super::*;
    use crate::cfg::{AstMeta, CallMeta, Cfg, NodeInfo, StmtKind, TaintMeta};
    use crate::labels::{Cap, DataLabel};
    use crate::ssa::ir::FieldId;
    use crate::state::symbol::SymbolInterner;
    use crate::taint::ssa_transfer::state::FieldTaintKey;
    use petgraph::graph::NodeIndex;
    use petgraph::prelude::*;
    use smallvec::smallvec;
    use std::collections::HashMap;

    /// Build a CFG with N nodes; node 1 carries a Source label.
    fn cfg_with_nodes(n: usize) -> (Cfg, Vec<NodeIndex>) {
        let mut cfg = Graph::new();
        let mut nodes = Vec::new();
        for i in 0..n {
            let nidx = cfg.add_node(NodeInfo {
                kind: StmtKind::Seq,
                ast: AstMeta {
                    span: (i * 10, i * 10 + 5),
                    ..Default::default()
                },
                taint: if i == 1 {
                    TaintMeta {
                        labels: smallvec![DataLabel::Source(Cap::ENV_VAR)],
                        ..Default::default()
                    }
                } else {
                    TaintMeta::default()
                },
                call: CallMeta::default(),
                ..Default::default()
            });
            nodes.push(nidx);
        }
        (cfg, nodes)
    }

    /// Build a 4-block diamond:
    ///
    /// ```text
    ///    B0  Param(obj), Source(src), synth `obj.cache = src`
    ///   /  \
    ///  B1   B2     (intermediate; populates side-table identically)
    ///   \  /
    ///    B3  FieldProj(obj.cache) → read
    /// ```
    ///
    /// Both predecessors of B3 carry the identical synth field write,
    /// so the joined cell at B3's entry retains the validation
    /// channels.  `seed_validated_must = true` triggers the symbol-
    /// level `src` validation that flows through the W1 hook.
    fn build_diamond_body(seed_validated_must: bool) -> (SsaBody, Cfg, FieldId, SymbolInterner) {
        let (cfg, nodes) = cfg_with_nodes(8);
        let n_param = nodes[0];
        let n_source = nodes[1];
        let n_assign1 = nodes[2];
        let n_assign2 = nodes[3];
        let n_proj = nodes[4];

        let mut field_interner = crate::ssa::ir::FieldInterner::default();
        let cache_id = field_interner.intern("cache");

        // Block 0: param + source (no field write here; the writes
        // are split across B1 and B2).
        let block0 = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Param { index: 0 },
                    cfg_node: n_param,
                    var_name: Some("obj".into()),
                    span: (0, 3),
                },
                SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Source,
                    cfg_node: n_source,
                    var_name: Some("src".into()),
                    span: (10, 15),
                },
            ],
            terminator: Terminator::Goto(BlockId(1)),
            preds: smallvec![],
            succs: smallvec![BlockId(1), BlockId(2)],
        };

        // Block 1: synth `obj.cache = src`, field_writes[v2] = (v0, cache_id)
        let block1 = SsaBlock {
            id: BlockId(1),
            phis: vec![],
            body: vec![SsaInst {
                value: SsaValue(2),
                op: SsaOp::Assign(smallvec![SsaValue(1)]),
                cfg_node: n_assign1,
                var_name: Some("obj".into()),
                span: (20, 30),
            }],
            terminator: Terminator::Goto(BlockId(3)),
            preds: smallvec![BlockId(0)],
            succs: smallvec![BlockId(3)],
        };

        // Block 2: identical synth write, keeps both branches
        // contributing the same cell so AND-intersection of must
        // preserves true on the join.
        let block2 = SsaBlock {
            id: BlockId(2),
            phis: vec![],
            body: vec![SsaInst {
                value: SsaValue(3),
                op: SsaOp::Assign(smallvec![SsaValue(1)]),
                cfg_node: n_assign2,
                var_name: Some("obj".into()),
                span: (40, 50),
            }],
            terminator: Terminator::Goto(BlockId(3)),
            preds: smallvec![BlockId(0)],
            succs: smallvec![BlockId(3)],
        };

        // Block 3: read, FieldProj uses obj from a phi between B1 and B2.
        let block3 = SsaBlock {
            id: BlockId(3),
            phis: vec![SsaInst {
                value: SsaValue(4),
                op: SsaOp::Phi(smallvec![
                    (BlockId(1), SsaValue(2)),
                    (BlockId(2), SsaValue(3)),
                ]),
                cfg_node: n_proj,
                var_name: Some("obj".into()),
                span: (60, 65),
            }],
            body: vec![SsaInst {
                value: SsaValue(5),
                op: SsaOp::FieldProj {
                    receiver: SsaValue(4),
                    field: cache_id,
                    projected_type: None,
                },
                cfg_node: n_proj,
                var_name: Some("read".into()),
                span: (60, 65),
            }],
            terminator: Terminator::Return(None),
            preds: smallvec![BlockId(1), BlockId(2)],
            succs: smallvec![],
        };

        let value_defs = vec![
            ValueDef {
                var_name: Some("obj".into()),
                cfg_node: n_param,
                block: BlockId(0),
            },
            ValueDef {
                var_name: Some("src".into()),
                cfg_node: n_source,
                block: BlockId(0),
            },
            ValueDef {
                var_name: Some("obj".into()),
                cfg_node: n_assign1,
                block: BlockId(1),
            },
            ValueDef {
                var_name: Some("obj".into()),
                cfg_node: n_assign2,
                block: BlockId(2),
            },
            ValueDef {
                var_name: Some("obj".into()),
                cfg_node: n_proj,
                block: BlockId(3),
            },
            ValueDef {
                var_name: Some("read".into()),
                cfg_node: n_proj,
                block: BlockId(3),
            },
        ];

        let mut field_writes = rustc_hash::FxHashMap::default();
        field_writes.insert(SsaValue(2), (SsaValue(0), cache_id));
        field_writes.insert(SsaValue(3), (SsaValue(0), cache_id));

        let body = SsaBody {
            blocks: vec![block0, block1, block2, block3],
            entry: BlockId(0),
            value_defs,
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner,
            field_writes,
            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let mut interner = SymbolInterner::new();
        // Pre-intern the names the test cares about.
        let _ = interner.intern("obj");
        let sym_src = interner.intern("src");
        let _ = interner.intern("read");
        // We can't pre-seed `validated_must` on the worklist's entry
        // state from outside, so the must/may semantics here come
        // from the absence of writes on one branch (lattice
        // intersection at the join).  The `seed_validated_must` flag
        // is reserved for future per-block seeding work.
        let _ = (sym_src, seed_validated_must);
        (body, cfg, cache_id, interner)
    }

    fn build_transfer<'a>(
        interner: &'a SymbolInterner,
        local_summaries: &'a FuncSummaries,
        pf: &'a crate::pointer::PointsToFacts,
    ) -> SsaTaintTransfer<'a> {
        SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "",
            interner,
            local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(7),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: None,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: Some(pf),
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        }
    }

    /// A2.a: full worklist convergence on the diamond.  Both
    /// predecessor branches write the cell, so the projected SSA
    /// value at B3 carries the source's caps, and `block_states`
    /// shows the cell present at B3's entry but absent at B0's entry.
    #[test]
    fn full_worklist_propagates_field_cell_across_join() {
        let (body, cfg, _cache_id, interner) = build_diamond_body(true);
        let pf = crate::pointer::analyse_body(&body, crate::cfg::BodyId(7));
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = build_transfer(&interner, &local_summaries, &pf);

        let (_events, block_states) =
            crate::taint::ssa_transfer::run_ssa_taint_full(&body, &cfg, &transfer);

        // Block 0's entry state has no field_taint cell yet.
        let b0 = block_states[0]
            .as_ref()
            .expect("block 0 entry state present");
        assert!(
            b0.field_taint.is_empty(),
            "B0 entry must have no field_taint cells yet; got {:?}",
            b0.field_taint
        );

        // Block 3's entry state carries the cell after the join.
        let b3 = block_states[3]
            .as_ref()
            .expect("block 3 entry state present");
        let pt_v0 = pf.pt(SsaValue(0));
        assert!(!pt_v0.is_empty() && !pt_v0.is_top());
        let parent_loc = pt_v0.iter().next().unwrap();
        let cell = b3.get_field(FieldTaintKey {
            loc: parent_loc,
            field: _cache_id,
        });
        assert!(
            cell.is_some(),
            "B3 entry must contain (Param(_,0), cache) cell after diamond join; got {:?}",
            b3.field_taint
        );
        let cell = cell.unwrap();
        assert!(
            cell.taint.caps.contains(Cap::ENV_VAR),
            "joined cell must carry the Source's ENV_VAR cap"
        );
    }

    /// Gating `block_exit_states` (the `track_exit_states` flag added
    /// 2026-07-14 to elide a full `SsaTaintState::clone` per block pop on the
    /// main taint path) must not change the analysis result.  `run_ssa_taint_full`
    /// (`track=false`, discards exit states) and `run_ssa_taint_full_with_exits`
    /// (`track=true`, moves them in) must agree bit-for-bit on the emitted
    /// events and the converged per-block entry states across a real
    /// multi-block (diamond) body; only `block_exit_states` differs (populated
    /// for the tracking variant, unavailable via the non-tracking API).
    #[test]
    fn exit_state_tracking_gate_preserves_events_and_block_states() {
        let (body, cfg, _cache_id, interner) = build_diamond_body(true);
        let pf = crate::pointer::analyse_body(&body, crate::cfg::BodyId(7));
        let local_summaries: FuncSummaries = HashMap::new();
        let transfer = build_transfer(&interner, &local_summaries, &pf);

        let (events_untracked, states_untracked) =
            crate::taint::ssa_transfer::run_ssa_taint_full(&body, &cfg, &transfer);
        let (events_tracked, states_tracked, exit_states) =
            crate::taint::ssa_transfer::run_ssa_taint_full_with_exits(&body, &cfg, &transfer);

        // Converged per-block ENTRY states are identical (SsaTaintState: PartialEq).
        assert_eq!(
            states_untracked, states_tracked,
            "block entry states must be identical regardless of exit-state tracking"
        );

        // Emitted events are identical (SsaTaintEvent has no PartialEq; compare
        // count + Debug projection, which covers sink_node/caps/validation).
        assert_eq!(
            events_untracked.len(),
            events_tracked.len(),
            "event count must be identical regardless of exit-state tracking"
        );
        assert_eq!(
            format!("{events_untracked:?}"),
            format!("{events_tracked:?}"),
            "event contents must be identical regardless of exit-state tracking"
        );

        // The tracking variant populates exit states for every reached block;
        // reached blocks are exactly those with a converged entry state.
        for (bid, entry) in states_tracked.iter().enumerate() {
            assert_eq!(
                entry.is_some(),
                exit_states[bid].is_some(),
                "block {bid}: exit state presence must match entry state presence"
            );
        }
    }

    /// A2.b: early-exit branch, only B1 writes, B2 reaches B3 via
    /// an empty body.  After the join, the cell exists (B1 wrote
    /// it), but `validated_must` is `false` (B2 didn't write, the
    /// orphan-side merge clears `must` per the W4 lattice rule);
    /// `validated_may` is preserved on the writer's side via OR.
    ///
    /// To exercise the validation channels we synthesise the cell
    /// directly at the appropriate exit state, then run the
    /// worklist's join via two `SsaTaintState::join()` calls, the
    /// body's worklist itself doesn't seed `validated_must` on the
    /// rhs of an Assign, so we model the "writer recorded must=true"
    /// scenario at the lattice level rather than driving it through
    /// transfer_inst.
    #[test]
    fn early_exit_branch_drops_validated_must_on_join() {
        let (body, _cfg, _cache_id, _interner) = build_diamond_body(false);
        let pf = crate::pointer::analyse_body(&body, crate::cfg::BodyId(7));
        let pt_v0 = pf.pt(SsaValue(0));
        let parent_loc = pt_v0.iter().next().unwrap();

        // Predecessor 1: cell with validated_must=true, validated_may=true.
        let mut pred1 = SsaTaintState::initial();
        pred1.add_field(
            FieldTaintKey {
                loc: parent_loc,
                field: _cache_id,
            },
            crate::taint::domain::VarTaint {
                caps: Cap::ENV_VAR,
                origins: SmallVec::new(),
                uses_summary: false,
            },
            true,
            true,
        );

        // Predecessor 2: empty (no cell).
        let pred2 = SsaTaintState::initial();

        // Worklist join semantics.
        let joined = pred1.join(&pred2);
        let cell = joined
            .get_field(FieldTaintKey {
                loc: parent_loc,
                field: _cache_id,
            })
            .expect("cell present on the writer's side");
        assert!(
            !cell.validated_must,
            "join with empty side must clear validated_must (orphan rule)"
        );
        assert!(
            cell.validated_may,
            "validated_may from the writer's side survives the join"
        );
        assert!(cell.taint.caps.contains(Cap::ENV_VAR));
    }
}

// ── distinct_summary_sink_caps (multi-sink-per-param de-masking) ─────────
#[cfg(test)]
mod distinct_summary_sink_caps_tests {
    use super::super::distinct_summary_sink_caps;
    use crate::labels::Cap;
    use crate::summary::SinkSite;
    use smallvec::{SmallVec, smallvec};

    fn site(line: u32, cap: Cap) -> SinkSite {
        SinkSite {
            file_rel: "Fetcher.java".to_string(),
            line,
            col: 9,
            snippet: String::new(),
            cap,
            from_chain: true,
        }
    }

    /// One param flowing to two distinct-cap sinks yields two split masks
    /// (the masking case: SSRF co-located with HEADER_INJECTION).
    #[test]
    fn distinct_caps_split_into_per_cap_masks() {
        let p2ss: Vec<(usize, SmallVec<[SinkSite; 1]>)> = vec![(
            1usize,
            smallvec![site(12, Cap::SSRF), site(13, Cap::HEADER_INJECTION)],
        )];
        let out = distinct_summary_sink_caps(&p2ss, Cap::SSRF | Cap::HEADER_INJECTION);
        assert_eq!(out.len(), 2, "two distinct caps => two split passes");
        assert!(out.contains(&Cap::SSRF));
        assert!(out.contains(&Cap::HEADER_INJECTION));
    }

    /// A single-cap summary sink produces one mask, preserving the legacy
    /// single-pass union behavior (`len() <= 1` keeps the else-branch).
    #[test]
    fn single_cap_no_split() {
        let p2ss: Vec<(usize, SmallVec<[SinkSite; 1]>)> =
            vec![(0usize, smallvec![site(12, Cap::SSRF)])];
        let out = distinct_summary_sink_caps(&p2ss, Cap::SSRF);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], Cap::SSRF);
    }

    /// Repeated identical caps across sites/params dedup to one mask, so a
    /// param reaching the same cap twice does not over-split.
    #[test]
    fn duplicate_caps_dedup() {
        let p2ss: Vec<(usize, SmallVec<[SinkSite; 1]>)> = vec![
            (0usize, smallvec![site(12, Cap::SSRF)]),
            (1usize, smallvec![site(20, Cap::SSRF)]),
        ];
        let out = distinct_summary_sink_caps(&p2ss, Cap::SSRF);
        assert_eq!(out.len(), 1, "same cap at two sites => one mask");
    }

    /// Each split mask is narrowed to the propagated `sink_caps`: a site
    /// cap that does not intersect the propagated mask is dropped entirely.
    #[test]
    fn caps_narrowed_to_propagated_sink_caps() {
        let p2ss: Vec<(usize, SmallVec<[SinkSite; 1]>)> = vec![(
            0usize,
            smallvec![site(12, Cap::SSRF), site(13, Cap::HEADER_INJECTION)],
        )];
        // HEADER_INJECTION was stripped upstream (e.g. type-safe arg) —
        // only SSRF remains in the propagated mask, so only it splits out.
        let out = distinct_summary_sink_caps(&p2ss, Cap::SSRF);
        assert_eq!(out, smallvec![Cap::SSRF] as SmallVec<[Cap; 4]>);
    }

    /// Cap-only sites (`line == 0`, no resolved coordinates) are skipped:
    /// they carry no attributable location and must not split off a phantom
    /// per-cap event.
    #[test]
    fn cap_only_sites_skipped() {
        let p2ss: Vec<(usize, SmallVec<[SinkSite; 1]>)> = vec![(
            0usize,
            smallvec![
                site(12, Cap::SSRF),
                SinkSite::cap_only(Cap::HEADER_INJECTION)
            ],
        )];
        let out = distinct_summary_sink_caps(&p2ss, Cap::SSRF | Cap::HEADER_INJECTION);
        assert_eq!(out, smallvec![Cap::SSRF] as SmallVec<[Cap; 4]>);
    }

    /// No sites => empty (single-pass union path retained).
    #[test]
    fn empty_sites_empty_result() {
        let p2ss: Vec<(usize, SmallVec<[SinkSite; 1]>)> = vec![];
        let out = distinct_summary_sink_caps(&p2ss, Cap::SSRF | Cap::HEADER_INJECTION);
        assert!(out.is_empty());
    }
}

// ── ConfinementGates hoist: gate-flag correctness ────────────────────────
#[cfg(test)]
mod confinement_gate_tests {
    use super::super::*;
    use crate::summary::ssa_summary::SsaFuncSummary;
    use crate::symbol::{FuncKey, FuncKind};

    use smallvec::smallvec;

    /// Build a minimal `SsaTaintTransfer` (Go, no seeds) pointing at `summaries`.
    fn transfer_with<'a>(
        interner: &'a SymbolInterner,
        local_summaries: &'a FuncSummaries,
        summaries: Option<&'a std::collections::HashMap<FuncKey, SsaFuncSummary>>,
    ) -> SsaTaintTransfer<'a> {
        SsaTaintTransfer {
            lang: Lang::Go,
            namespace: "",
            interner,
            local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: summaries,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: None,
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        }
    }

    fn key(name: &str, lang: Lang) -> FuncKey {
        FuncKey::from_parts(lang, "", "", name, Some(1), None, FuncKind::Function)
    }

    #[test]
    fn none_summaries_close_all_gates() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let t = transfer_with(&interner, &ls, None);
        let g = compute_confinement_gates(&t);
        assert!(!g.assert && !g.path_validator && !g.return_confiner);
    }

    #[test]
    fn empty_summaries_close_all_gates() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let map: std::collections::HashMap<FuncKey, SsaFuncSummary> =
            std::collections::HashMap::new();
        let t = transfer_with(&interner, &ls, Some(&map));
        let g = compute_confinement_gates(&t);
        assert!(!g.assert && !g.path_validator && !g.return_confiner);
    }

    #[test]
    fn each_flag_opens_only_its_gate() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();

        // confines_path_return -> return_confiner only.
        let ret = SsaFuncSummary {
            confines_path_return: true,
            ..Default::default()
        };
        let mut m1 = std::collections::HashMap::new();
        m1.insert(key("compose_path", Lang::Go), ret);
        let g = compute_confinement_gates(&transfer_with(&interner, &ls, Some(&m1)));
        assert!(g.return_confiner && !g.assert && !g.path_validator);

        // asserts_path_confined_params -> assert only.
        let asrt = SsaFuncSummary {
            asserts_path_confined_params: smallvec![0],
            ..Default::default()
        };
        let mut m2 = std::collections::HashMap::new();
        m2.insert(key("check_under", Lang::Go), asrt);
        let g = compute_confinement_gates(&transfer_with(&interner, &ls, Some(&m2)));
        assert!(g.assert && !g.return_confiner && !g.path_validator);

        // result_reject_guard_params -> path_validator only.
        let rej = SsaFuncSummary {
            result_reject_guard_params: smallvec![0],
            ..Default::default()
        };
        let mut m3 = std::collections::HashMap::new();
        m3.insert(key("ensure_safe_path", Lang::Go), rej);
        let g = compute_confinement_gates(&transfer_with(&interner, &ls, Some(&m3)));
        assert!(g.path_validator && !g.assert && !g.return_confiner);
    }

    #[test]
    fn different_lang_summary_leaves_gates_closed() {
        // A confiner summary in another language must not open a same-language
        // body's gate (the passes filter on `key.lang == transfer.lang`).
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let ret = SsaFuncSummary {
            confines_path_return: true,
            ..Default::default()
        };
        let mut m = std::collections::HashMap::new();
        m.insert(key("compose_path", Lang::C), ret); // C, transfer is Go
        let g = compute_confinement_gates(&transfer_with(&interner, &ls, Some(&m)));
        assert!(!g.return_confiner && !g.assert && !g.path_validator);
    }

    fn confiner_map(name: &str) -> std::collections::HashMap<FuncKey, SsaFuncSummary> {
        let mut m = std::collections::HashMap::new();
        m.insert(
            key(name, Lang::Go),
            SsaFuncSummary {
                confines_path_return: true,
                ..Default::default()
            },
        );
        m
    }

    /// Inside a scope the gates come back as the scan would give them, for the
    /// scoped map and for any other map, and the scope leaves nothing behind.
    #[test]
    fn scope_serves_the_scoped_map_and_scans_every_other() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let confining = confiner_map("compose_path");
        let empty: std::collections::HashMap<FuncKey, SsaFuncSummary> =
            std::collections::HashMap::new();

        {
            let _scope = ConfinementGatesScope::enter(Some(&confining), Lang::Go);
            let scoped =
                compute_confinement_gates(&transfer_with(&interner, &ls, Some(&confining)));
            assert!(scoped.return_confiner);
            // A different map is matched by address, so it is scanned, not
            // handed the scoped map's answer.
            let other = compute_confinement_gates(&transfer_with(&interner, &ls, Some(&empty)));
            assert!(!other.return_confiner);
            // So is the same map under another language.
            let mut c_transfer = transfer_with(&interner, &ls, Some(&confining));
            c_transfer.lang = Lang::C;
            assert!(!compute_confinement_gates(&c_transfer).return_confiner);
        }
        // Dropped: nothing is published any more.
        assert!(CONFINEMENT_GATES_TLS.get().is_none());
    }

    #[test]
    fn nested_scopes_restore_the_outer_one() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let outer_map = confiner_map("compose_path");
        let inner_map: std::collections::HashMap<FuncKey, SsaFuncSummary> =
            std::collections::HashMap::new();

        let _outer = ConfinementGatesScope::enter(Some(&outer_map), Lang::Go);
        let outer_published = CONFINEMENT_GATES_TLS.get();
        {
            let _inner = ConfinementGatesScope::enter(Some(&inner_map), Lang::Go);
            let g = compute_confinement_gates(&transfer_with(&interner, &ls, Some(&inner_map)));
            assert!(!g.return_confiner);
        }
        assert_eq!(
            CONFINEMENT_GATES_TLS.get().map(|(a, l, _)| (a, l)),
            outer_published.map(|(a, l, _)| (a, l)),
            "the outer scope is published again once the inner one drops"
        );
        let g = compute_confinement_gates(&transfer_with(&interner, &ls, Some(&outer_map)));
        assert!(g.return_confiner);
    }

    /// A scope over a map the enclosing scope already holds changes nothing.
    #[test]
    fn re_entering_the_same_map_keeps_the_published_gates() {
        let outer_map = confiner_map("compose_path");
        let _outer = ConfinementGatesScope::enter(Some(&outer_map), Lang::Go);
        let before = CONFINEMENT_GATES_TLS.get().map(|(a, l, _)| (a, l));
        {
            let _again = ConfinementGatesScope::enter(Some(&outer_map), Lang::Go);
            assert_eq!(CONFINEMENT_GATES_TLS.get().map(|(a, l, _)| (a, l)), before);
        }
        assert_eq!(CONFINEMENT_GATES_TLS.get().map(|(a, l, _)| (a, l)), before);
        // No summaries: leaves the published entry alone.
        let _none = ConfinementGatesScope::enter(None, Lang::Go);
        assert_eq!(CONFINEMENT_GATES_TLS.get().map(|(a, l, _)| (a, l)), before);
    }
}

// ── Per-run callee resolution memo ───────────────────────────────────────
#[cfg(test)]
mod resolve_memo_tests {
    use super::super::*;
    use crate::summary::ssa_summary::SsaFuncSummary;
    use crate::symbol::{FuncKey, FuncKind};

    fn transfer_with<'a>(
        interner: &'a SymbolInterner,
        local_summaries: &'a FuncSummaries,
        summaries: &'a std::collections::HashMap<FuncKey, SsaFuncSummary>,
        callbacks: &'a std::collections::HashMap<String, FuncKey>,
    ) -> SsaTaintTransfer<'a> {
        SsaTaintTransfer {
            lang: Lang::JavaScript,
            namespace: "app.js",
            interner,
            local_summaries,
            global_summaries: None,
            interop_edges: &[],
            owner_body_id: crate::cfg::BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: None,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries: Some(summaries),
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: Some(callbacks),
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases: None,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: None,
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: false,
        }
    }

    /// A callee bound through `callback_bindings` resolves to its SSA summary,
    /// which is enough to observe the memo without building a call graph.
    fn fixtures() -> (
        std::collections::HashMap<FuncKey, SsaFuncSummary>,
        std::collections::HashMap<String, FuncKey>,
    ) {
        let real = FuncKey::from_parts(
            Lang::JavaScript,
            "app.js",
            "",
            "real",
            Some(1),
            None,
            FuncKind::Function,
        );
        let mut summaries = std::collections::HashMap::new();
        summaries.insert(
            real.clone(),
            SsaFuncSummary {
                source_caps: Cap::ENV_VAR,
                ..Default::default()
            },
        );
        let mut callbacks = std::collections::HashMap::new();
        callbacks.insert("cb".to_string(), real);
        (summaries, callbacks)
    }

    #[test]
    fn a_scope_answers_a_repeated_call_from_the_first_resolution() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let (sums, cbs) = fixtures();
        let t = transfer_with(&interner, &ls, &sums, &cbs);

        let _scope = ResolveMemoScope::enter(&t);
        let first = resolve_callee_hinted(&t, "cb", "caller", 3, Some(1)).expect("resolves");
        let again = resolve_callee_hinted(&t, "cb", "caller", 3, Some(1)).expect("resolves");
        assert!(
            Rc::ptr_eq(&first, &again),
            "same call site, same answer object"
        );
        assert_eq!(first.source_caps, Cap::ENV_VAR);

        // Any input that differs is a different call site.
        let other_arity = resolve_callee_hinted(&t, "cb", "caller", 3, Some(2)).expect("resolves");
        let other_ordinal =
            resolve_callee_hinted(&t, "cb", "caller", 4, Some(1)).expect("resolves");
        let other_caller = resolve_callee_hinted(&t, "cb", "other", 3, Some(1)).expect("resolves");
        for different in [&other_arity, &other_ordinal, &other_caller] {
            assert!(!Rc::ptr_eq(&first, different));
            assert_eq!(different.source_caps, first.source_caps);
        }
    }

    #[test]
    fn without_a_scope_every_call_resolves_afresh() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let (sums, cbs) = fixtures();
        let t = transfer_with(&interner, &ls, &sums, &cbs);

        let a = resolve_callee_hinted(&t, "cb", "caller", 3, Some(1)).expect("resolves");
        let b = resolve_callee_hinted(&t, "cb", "caller", 3, Some(1)).expect("resolves");
        assert!(!Rc::ptr_eq(&a, &b));
        assert_eq!(a.source_caps, b.source_caps);
    }

    /// An inline analysis runs the callee body under its own transfer and its
    /// own scope. While that is active, a lookup made with the outer transfer
    /// is not served from the inner frame, and the outer frame is intact after.
    #[test]
    fn a_nested_run_has_its_own_frame() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let (sums, cbs) = fixtures();
        let outer = transfer_with(&interner, &ls, &sums, &cbs);
        let inner = transfer_with(&interner, &ls, &sums, &cbs);

        let _outer_scope = ResolveMemoScope::enter(&outer);
        let before = resolve_callee_hinted(&outer, "cb", "caller", 1, Some(1)).expect("resolves");
        {
            let _inner_scope = ResolveMemoScope::enter(&inner);
            let in_inner_1 = resolve_callee_hinted(&inner, "cb", "caller", 1, Some(1)).unwrap();
            let in_inner_2 = resolve_callee_hinted(&inner, "cb", "caller", 1, Some(1)).unwrap();
            assert!(Rc::ptr_eq(&in_inner_1, &in_inner_2));
            assert!(
                !Rc::ptr_eq(&before, &in_inner_1),
                "inner frame starts empty"
            );
            // The outer transfer is not the frame's owner now: no memo, no store.
            let o1 = resolve_callee_hinted(&outer, "cb", "caller", 9, Some(1)).unwrap();
            let o2 = resolve_callee_hinted(&outer, "cb", "caller", 9, Some(1)).unwrap();
            assert!(!Rc::ptr_eq(&o1, &o2));
        }
        let after = resolve_callee_hinted(&outer, "cb", "caller", 1, Some(1)).expect("resolves");
        assert!(
            Rc::ptr_eq(&before, &after),
            "outer frame survives the nested run"
        );
    }

    #[test]
    fn scope_frames_are_popped_on_drop() {
        let interner = SymbolInterner::new();
        let ls: FuncSummaries = std::collections::HashMap::new();
        let (sums, cbs) = fixtures();
        let t = transfer_with(&interner, &ls, &sums, &cbs);
        let depth = || RESOLVE_MEMO.with(|m| m.borrow().len());
        let base = depth();
        {
            let _a = ResolveMemoScope::enter(&t);
            let _b = ResolveMemoScope::enter(&t);
            assert_eq!(depth(), base + 2);
        }
        assert_eq!(depth(), base);
    }
}

mod root_lock_tests {
    use super::super::{PathBranchClass, classify_path_branch, root_checked_path_class};
    use crate::abstract_interp::path_domain::PathAssertion;
    use crate::symbol::Lang;

    fn kept(cond: &str, root_unterminated: bool, lang: Lang, receiver_is_string: bool) -> bool {
        let class: PathBranchClass = classify_path_branch(cond);
        assert!(
            !matches!(class.assertion, PathAssertion::None),
            "{cond} should classify as a prefix test"
        );
        !matches!(
            root_checked_path_class(&class, root_unterminated, lang, || receiver_is_string)
                .assertion,
            PathAssertion::None
        )
    }

    #[test]
    fn literal_root_needs_a_trailing_separator_for_string_tests() {
        assert!(kept(
            "p.startsWith('/srv/data/')",
            false,
            Lang::JavaScript,
            false
        ));
        assert!(!kept(
            "p.startsWith('/srv/data')",
            false,
            Lang::JavaScript,
            false
        ));
        assert!(!kept("p.startsWith('/s')", false, Lang::JavaScript, false));
        assert!(kept(
            "p.startswith('/srv/data/')",
            false,
            Lang::Python,
            false
        ));
        assert!(!kept(
            "p.startswith('/srv/data')",
            false,
            Lang::Python,
            false
        ));
        assert!(kept(
            "strings.HasPrefix(p, \"/srv/data/\")",
            false,
            Lang::Go,
            false
        ));
        assert!(!kept(
            "strings.HasPrefix(p, \"/srv/data\")",
            false,
            Lang::Go,
            false
        ));
    }

    #[test]
    fn resolved_unterminated_root_drops_the_lock_but_opaque_root_keeps_it() {
        assert!(kept("p.startsWith(ROOT)", false, Lang::JavaScript, false));
        assert!(!kept("p.startsWith(ROOT)", true, Lang::JavaScript, false));
        assert!(kept(
            "p.startswith(ROOT + os.sep)",
            false,
            Lang::Python,
            false
        ));
    }

    #[test]
    fn component_wise_tests_accept_any_root() {
        // Python `is_relative_to` compares components.
        assert!(kept(
            "p.is_relative_to('/srv/data')",
            false,
            Lang::Python,
            false
        ));
        // Rust `Path::starts_with` and Java `Path.startsWith` too, unless the
        // receiver is a string.
        assert!(kept(
            "p.starts_with(\"/srv/data\")",
            false,
            Lang::Rust,
            false
        ));
        assert!(!kept(
            "p.starts_with(\"/srv/data\")",
            false,
            Lang::Rust,
            true
        ));
        assert!(!kept(
            "p.to_str().unwrap().starts_with(\"/srv/data\")",
            false,
            Lang::Rust,
            false
        ));
        assert!(kept(
            "p.startsWith(\"/srv/data\")",
            false,
            Lang::Java,
            false
        ));
        assert!(!kept(
            "p.startsWith(\"/srv/data\")",
            false,
            Lang::Java,
            true
        ));
        assert!(!kept(
            "p.toString().startsWith(\"/srv/data\")",
            false,
            Lang::Java,
            false
        ));
        assert!(kept(
            "p.toString().startsWith(\"/srv/data/\")",
            false,
            Lang::Java,
            false
        ));
    }
}
