use super::lattice::Lattice;
use crate::cfg::{Cfg, EdgeKind, NodeInfo};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum tracked variables per function (guarded degradation).
pub const MAX_TRACKED_VARS: usize = 64;

/// Default worklist iteration budget.
pub const MAX_WORKLIST_ITERATIONS: usize = 100_000;

/// Generic transfer function trait for forward dataflow analysis.
///
/// Domains implement this to define how abstract state flows through
/// CFG nodes and what events (findings) are emitted.
pub trait Transfer<S: Lattice> {
    /// Side-channel events emitted during transfer (e.g., findings, violations).
    type Event: Clone;

    /// Apply the transfer function to a node, returning the output state
    /// and any events.
    fn apply(
        &self,
        node: NodeIndex,
        info: &NodeInfo,
        edge: Option<EdgeKind>,
        state: S,
    ) -> (S, Vec<Self::Event>);

    /// Per-domain iteration budget. Defaults to [`MAX_WORKLIST_ITERATIONS`].
    fn iteration_budget(&self) -> usize {
        MAX_WORKLIST_ITERATIONS
    }

    /// Called when the budget is exhausted. Returns true if the engine
    /// should continue with the current (non-converged) state, false to bail.
    fn on_budget_exceeded(&self) -> bool {
        false
    }
}

/// Result of running the forward dataflow engine.
pub struct DataflowResult<S, E> {
    /// Converged state at the entry of each node.
    pub states: HashMap<NodeIndex, S>,
    /// Events emitted during the second pass over converged states.
    pub events: Vec<E>,
    /// Whether the analysis converged (false if budget was hit).
    #[allow(dead_code)]
    pub converged: bool,
}

/// Run a forward worklist dataflow analysis over the CFG.
///
/// Two-pass design:
/// - First pass: fixed-point iteration to converge states (no event collection).
/// - Second pass: single pass over converged states to collect events.
///
/// Termination is guaranteed by lattice finiteness + iteration budget.
pub fn run_forward<S: Lattice, T: Transfer<S>>(
    cfg: &Cfg,
    entry: NodeIndex,
    transfer: &T,
    initial: S,
) -> DataflowResult<S, T::Event> {
    let mut states: HashMap<NodeIndex, S> = HashMap::new();
    let budget = transfer.iteration_budget();

    // Initialize entry node
    states.insert(entry, initial);

    // ── First pass: fixed-point iteration (compute converged states) ──
    let _phase1_span = tracing::debug_span!("state_engine_phase1").entered();
    let mut worklist: VecDeque<NodeIndex> = VecDeque::new();
    let mut in_worklist: HashSet<NodeIndex> = HashSet::new();
    worklist.push_back(entry);
    in_worklist.insert(entry);

    let mut iterations: usize = 0;
    let mut converged = true;

    while let Some(node) = worklist.pop_front() {
        in_worklist.remove(&node);
        iterations += 1;
        if iterations > budget {
            let should_continue = transfer.on_budget_exceeded();
            if !should_continue {
                converged = false;
                break;
            }
            // Budget exceeded but transfer requested continuation, mark non-converged
            converged = false;
        }

        let node_state = match states.get(&node) {
            Some(s) => s.clone(),
            None => continue,
        };

        let edges: Vec<_> = cfg.edges(node).map(|e| (*e.weight(), e.target())).collect();

        // No outgoing edges, nothing to propagate (exit/dead end).
        if edges.is_empty() {
            continue;
        }

        for &(edge_kind, target) in &edges {
            // Skip redundant Seq edges when a True or False edge reaches the
            // same target. The CFG builder may emit both a Seq edge (from
            // build_sub chaining) and a True/False edge (from explicit If
            // wiring) to the same successor. The Seq edge carries no
            // branch-aware state, so it dilutes the auth elevation that
            // the True edge provides. Dropping it preserves correct semantics.
            if matches!(edge_kind, EdgeKind::Seq)
                && edges
                    .iter()
                    .any(|&(k, t)| t == target && matches!(k, EdgeKind::True | EdgeKind::False))
            {
                continue;
            }

            let info = &cfg[node];
            let (out_state, _events) =
                transfer.apply(node, info, Some(edge_kind), node_state.clone());

            // Join into target's state
            let target_state = states.get(&target);
            let new_target = match target_state {
                Some(existing) => existing.join(&out_state),
                None => out_state,
            };

            let changed = target_state.is_none_or(|existing| *existing != new_target);
            if changed {
                states.insert(target, new_target);
                if in_worklist.insert(target) {
                    worklist.push_back(target);
                }
            }
        }
    }

    tracing::debug!(iterations, converged, "state_engine_phase1 complete");
    drop(_phase1_span);

    // ── Second pass: single pass over converged states to collect events ──
    let _phase2_span = tracing::debug_span!("state_engine_phase2").entered();
    let mut events: Vec<T::Event> = Vec::new();
    let mut seen_edges: std::collections::HashSet<(NodeIndex, NodeIndex)> =
        std::collections::HashSet::new();

    for node in states.keys().copied().collect::<Vec<_>>() {
        let node_state = match states.get(&node) {
            Some(s) => s.clone(),
            None => continue,
        };

        let edges: Vec<_> = cfg.edges(node).map(|e| (*e.weight(), e.target())).collect();

        if edges.is_empty() {
            // Exit / dead end, apply transfer for event collection.
            let info = &cfg[node];
            let (_out_state, new_events) = transfer.apply(node, info, None, node_state);
            events.extend(new_events);
            continue;
        }

        for &(edge_kind, target) in &edges {
            // Same redundant-Seq-edge skip as the first pass.
            if matches!(edge_kind, EdgeKind::Seq)
                && edges
                    .iter()
                    .any(|&(k, t)| t == target && matches!(k, EdgeKind::True | EdgeKind::False))
            {
                continue;
            }
            if !seen_edges.insert((node, target)) {
                continue;
            }
            let info = &cfg[node];
            let (_out_state, new_events) =
                transfer.apply(node, info, Some(edge_kind), node_state.clone());
            events.extend(new_events);
        }
    }

    DataflowResult {
        states,
        events,
        converged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{CallMeta, EdgeKind, NodeInfo, StmtKind, TaintMeta};
    use crate::cfg_analysis::rules;
    use crate::state::domain::ResourceLifecycle;
    use crate::state::symbol::SymbolInterner;
    use crate::state::transfer::DefaultTransfer;
    use crate::symbol::Lang;
    use petgraph::Graph;

    fn make_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    #[test]
    fn linear_cfg_converges() {
        use crate::state::domain::ProductState;

        // Entry → fopen(f) → fclose(f) → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                defines: Some("f".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fopen".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let close_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                uses: vec!["f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fclose".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, close_node, EdgeKind::Seq);
        cfg.add_edge(close_node, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = run_forward(&cfg, entry, &transfer, ProductState::initial());

        // No events (clean open→close)
        assert!(result.events.is_empty());
        assert!(result.converged);

        // At exit, f should be CLOSED
        let sym_f = interner.get("f").unwrap();
        let exit_state = result.states.get(&exit).unwrap();
        assert_eq!(exit_state.resource.get(sym_f), ResourceLifecycle::CLOSED);
    }

    #[test]
    fn diamond_cfg_joins_states() {
        use crate::state::domain::ProductState;

        //         Entry
        //           |
        //         fopen(f)
        //           |
        //          If
        //         /    \
        //   fclose(f)  (no close)
        //         \    /
        //          Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                defines: Some("f".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fopen".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let close_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                uses: vec!["f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fclose".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let no_close = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, close_node, EdgeKind::True);
        cfg.add_edge(if_node, no_close, EdgeKind::False);
        cfg.add_edge(close_node, exit, EdgeKind::Seq);
        cfg.add_edge(no_close, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = run_forward(&cfg, entry, &transfer, ProductState::initial());

        // At exit, f should be OPEN | CLOSED (may-leak)
        let sym_f = interner.get("f").unwrap();
        let exit_state = result.states.get(&exit).unwrap();
        assert_eq!(
            exit_state.resource.get(sym_f),
            ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED
        );
    }

    // ── Budget / on_budget_exceeded tests ──────────────────────────────────

    /// Minimal lattice for budget tests.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct UnitState;

    impl Lattice for UnitState {
        fn bot() -> Self {
            UnitState
        }
        fn join(&self, _other: &Self) -> Self {
            UnitState
        }
        fn leq(&self, _other: &Self) -> bool {
            true
        }
    }

    /// Transfer that always bails on budget (returns false).
    struct BailTransfer;

    impl Transfer<UnitState> for BailTransfer {
        type Event = ();

        fn apply(
            &self,
            _node: NodeIndex,
            _info: &NodeInfo,
            _edge: Option<EdgeKind>,
            state: UnitState,
        ) -> (UnitState, Vec<()>) {
            (state, vec![])
        }

        fn iteration_budget(&self) -> usize {
            2 // very small budget
        }

        fn on_budget_exceeded(&self) -> bool {
            false // bail
        }
    }

    /// Transfer that continues on budget (returns true).
    struct ContinueTransfer;

    impl Transfer<UnitState> for ContinueTransfer {
        type Event = ();

        fn apply(
            &self,
            _node: NodeIndex,
            _info: &NodeInfo,
            _edge: Option<EdgeKind>,
            state: UnitState,
        ) -> (UnitState, Vec<()>) {
            (state, vec![])
        }

        fn iteration_budget(&self) -> usize {
            2
        }

        fn on_budget_exceeded(&self) -> bool {
            true // keep going
        }
    }

    fn make_chain_cfg() -> (Cfg, NodeIndex) {
        // Entry → A → B → C → Exit (4 iterations for the worklist)
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let a = cfg.add_node(make_node(StmtKind::Seq));
        let b = cfg.add_node(make_node(StmtKind::Seq));
        let c = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));
        cfg.add_edge(entry, a, EdgeKind::Seq);
        cfg.add_edge(a, b, EdgeKind::Seq);
        cfg.add_edge(b, c, EdgeKind::Seq);
        cfg.add_edge(c, exit, EdgeKind::Seq);
        (cfg, entry)
    }

    #[test]
    fn budget_exceeded_bail_stops_immediately_and_marks_non_converged() {
        let (cfg, entry) = make_chain_cfg();
        let result = run_forward(&cfg, entry, &BailTransfer, UnitState);

        // Must NOT be converged when on_budget_exceeded returns false
        assert!(!result.converged, "bail transfer must mark converged=false");
    }

    #[test]
    fn budget_exceeded_continue_marks_non_converged() {
        let (cfg, entry) = make_chain_cfg();
        let result = run_forward(&cfg, entry, &ContinueTransfer, UnitState);

        // Even when continuing past budget, converged must be false
        assert!(
            !result.converged,
            "continue-past-budget must still mark converged=false"
        );
    }

    #[test]
    fn within_budget_marks_converged() {
        // Use a generous budget so the analysis converges normally
        struct GenerousTransfer;
        impl Transfer<UnitState> for GenerousTransfer {
            type Event = ();
            fn apply(
                &self,
                _node: NodeIndex,
                _info: &NodeInfo,
                _edge: Option<EdgeKind>,
                state: UnitState,
            ) -> (UnitState, Vec<()>) {
                (state, vec![])
            }
            fn iteration_budget(&self) -> usize {
                100_000
            }
        }

        let (cfg, entry) = make_chain_cfg();
        let result = run_forward(&cfg, entry, &GenerousTransfer, UnitState);
        assert!(result.converged, "within-budget analysis should converge");
    }

    #[test]
    fn worklist_membership_dedup_with_nodeindex() {
        use petgraph::graph::NodeIndex;
        use std::collections::{HashSet, VecDeque};

        let mut wl: VecDeque<NodeIndex> = VecDeque::new();
        let mut in_wl: HashSet<NodeIndex> = HashSet::new();

        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let n2 = NodeIndex::new(2);

        assert!(in_wl.insert(n0));
        wl.push_back(n0);

        assert!(in_wl.insert(n1));
        wl.push_back(n1);

        // Duplicate n0, should not insert
        assert!(!in_wl.insert(n0));
        // wl still has only 2 entries
        assert_eq!(wl.len(), 2);

        let popped = wl.pop_front().unwrap();
        in_wl.remove(&popped);
        assert_eq!(popped, n0);
        assert!(!in_wl.contains(&n0));
        assert!(in_wl.contains(&n1));

        // Re-enqueue n0 (state changed)
        assert!(in_wl.insert(n0));
        wl.push_back(n0);

        assert!(in_wl.insert(n2));
        wl.push_back(n2);

        assert_eq!(wl.len(), 3);
        assert_eq!(in_wl.len(), 3);
    }

    // ── CFG-shape robustness ─────────────────────────────────────────────
    //
    // The audit flagged that `run_forward` had only linear/diamond test
    // shapes. These tests exercise edge cases that can trip up the
    // worklist algorithm: nodes the entry can't reach, a CFG with only
    // an entry node, irreducible flow with multiple paths into the
    // same loop body, and a self-loop. Each must terminate without
    // panicking and produce a sensible converged state.

    /// A node disconnected from the entry must NOT receive any state
    /// (it's unreachable). The engine processes only nodes reachable
    /// from the worklist seed; a quiescent unreachable node should
    /// stay absent from the result map.
    #[test]
    fn unreachable_nodes_get_no_state() {
        use crate::state::domain::ProductState;

        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let reachable = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));
        // Unreachable island: no edge from entry leads here.
        let orphan = cfg.add_node(make_node(StmtKind::Seq));
        let orphan_exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, reachable, EdgeKind::Seq);
        cfg.add_edge(reachable, exit, EdgeKind::Seq);
        cfg.add_edge(orphan, orphan_exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = run_forward(&cfg, entry, &transfer, ProductState::initial());
        assert!(result.converged);
        assert!(
            result.states.contains_key(&entry),
            "entry must have a state"
        );
        assert!(
            result.states.contains_key(&reachable),
            "reachable node must have a state"
        );
        assert!(
            !result.states.contains_key(&orphan),
            "orphan island must NOT receive any state"
        );
        assert!(
            !result.states.contains_key(&orphan_exit),
            "orphan exit must NOT receive any state"
        );
    }

    /// A single-node graph (entry only, no edges) is the minimal case.
    /// The engine must terminate immediately, mark converged, and leave
    /// the entry's initial state untouched.
    #[test]
    fn single_node_graph_terminates_immediately() {
        use crate::state::domain::ProductState;

        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = run_forward(&cfg, entry, &transfer, ProductState::initial());
        assert!(result.converged);
        assert!(
            result.states.contains_key(&entry),
            "single-node graph still seeds the entry state"
        );
    }

    /// Self-loop on a single node: `entry → A → A → … → exit`. The
    /// worklist must not livelock, once A's state is stable, the
    /// back-edge stops re-enqueueing it.
    #[test]
    fn self_loop_terminates() {
        use crate::state::domain::ProductState;

        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let a = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, a, EdgeKind::Seq);
        cfg.add_edge(a, a, EdgeKind::Back); // self-loop
        cfg.add_edge(a, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = run_forward(&cfg, entry, &transfer, ProductState::initial());
        assert!(result.converged, "self-loop must converge");
        assert!(result.states.contains_key(&exit));
    }

    /// Irreducible CFG: two distinct paths from entry both enter the
    /// same loop body, so the loop has multiple "entry points". This
    /// is the classic shape that breaks structured-loop assumptions
    /// (e.g., "every loop has a unique header"). The forward worklist
    /// must still terminate.
    ///
    /// Shape:
    ///     entry → a ─┐
    ///                ├→ loop_body ─→ exit
    ///     entry → b ─┘     ↑
    ///                      └─ back-edge from loop_body to itself
    #[test]
    fn irreducible_cfg_terminates() {
        use crate::state::domain::ProductState;

        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let a = cfg.add_node(make_node(StmtKind::Seq));
        let b = cfg.add_node(make_node(StmtKind::Seq));
        let loop_body = cfg.add_node(make_node(StmtKind::Loop));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, a, EdgeKind::Seq);
        cfg.add_edge(entry, b, EdgeKind::Seq);
        cfg.add_edge(a, loop_body, EdgeKind::Seq);
        cfg.add_edge(b, loop_body, EdgeKind::Seq);
        cfg.add_edge(loop_body, loop_body, EdgeKind::Back);
        cfg.add_edge(loop_body, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = run_forward(&cfg, entry, &transfer, ProductState::initial());
        assert!(
            result.converged,
            "irreducible CFG must still converge under run_forward"
        );
        // Every reachable node must have a state.
        for n in [entry, a, b, loop_body, exit] {
            assert!(result.states.contains_key(&n), "node {n:?} must be visited");
        }
    }
}
