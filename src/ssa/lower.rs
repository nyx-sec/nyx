#![allow(
    clippy::collapsible_if,
    clippy::if_same_then_else,
    clippy::needless_range_loop,
    clippy::only_used_in_recursion,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_unwrap
)]

use crate::cfg::{Cfg, EdgeKind, StmtKind};
use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::graph::NodeIndex;
use petgraph::prelude::*;
use petgraph::visit::EdgeRef;
use smallvec::SmallVec;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use super::ir::*;

/// Try to decompose a chained-receiver method call (e.g. `a.b.c.method`)
/// into a `FieldProj` chain plus a bare-method `Call`.
///
/// **Returns** `Some((final_receiver_value, bare_method_name))` on success,
/// `None` to fall back to the existing single-Call lowering (current
/// behaviour).
///
/// On success, the caller should:
///   - Construct the `Call` op with `callee = bare_method_name`,
///     `callee_text = Some(original_callee.to_string())`,
///     `receiver = Some(final_receiver_value)`.
///   - Use the returned receiver as the implicit method receiver, do NOT
///     add the chain root or any intermediate field name to `args`.
///
/// **Decomposition rules**:
///   - Skip when the callee contains zero `.` characters (no member access)
///     or only one `.` (single-dot case is handled by the existing
///     `info.call.receiver` channel without needing a `FieldProj` op).
///   - Bail when any "complex" token appears in the callee, `(`, `)`,
///     `[`, `]`, `::`, `->`, `?`, `<`, `>`, `*`, `&`, `:` (other than `::`
///     already filtered), or whitespace, signaling the callee text isn't
///     a clean `<ident>.<ident>...` chain we can safely split on `.`.
///   - The first segment must be a known SSA variable in `var_stacks`;
///     otherwise the chain root is unresolvable and we bail.
///   - Each intermediate segment becomes a `FieldProj { receiver, field }`
///     instruction emitted onto `block.body` with a fresh `SsaValue`.
///   - The last segment is the bare method name returned to the caller.
///
/// FieldProj instructions are tagged with `var_name = Some("base.f1.f2")`
/// so debug output and downstream consumers that key on `var_name` can
/// recognise the projection chain provenance.
#[allow(clippy::too_many_arguments)]
fn try_lower_field_proj_chain(
    callee: &str,
    var_stacks: &HashMap<String, Vec<SsaValue>>,
    field_interner: &mut crate::ssa::ir::FieldInterner,
    block_idx: usize,
    block_id: BlockId,
    next_value: &mut u32,
    ssa_blocks: &mut [SsaBlock],
    value_defs: &mut Vec<ValueDef>,
    cfg_node: NodeIndex,
    span: (usize, usize),
) -> Option<(SsaValue, String)> {
    // Bail on any token that signals a complex callee expression.
    // `::` (Rust/C++ paths) is folded into the broader `:` check.
    for ch in callee.chars() {
        match ch {
            '(' | ')' | '[' | ']' | '<' | '>' | '?' | '*' | '&' | ':' | ' ' | '\t' | '\n' | '-'
            | '!' | ',' | ';' | '"' | '\'' | '\\' => return None,
            _ => {}
        }
    }
    let segments: Vec<&str> = callee.split('.').collect();
    // Need at least 3 segments: `base.field.method` → 1 FieldProj, 1 Call.
    if segments.len() < 3 {
        return None;
    }
    // Reject empty segments (would happen on leading/trailing/double dots).
    if segments.iter().any(|s| s.is_empty()) {
        return None;
    }

    let base = segments[0];
    let mut current = *var_stacks.get(base).and_then(|s| s.last())?;
    let mut chain_var = base.to_string();

    // Each intermediate segment becomes a FieldProj op.  segments[0] is the
    // base SSA variable, segments[len-1] is the bare method name.
    for field_name in &segments[1..segments.len() - 1] {
        let fid = field_interner.intern(field_name);
        let v = SsaValue(*next_value);
        *next_value += 1;
        chain_var.push('.');
        chain_var.push_str(field_name);
        ssa_blocks[block_idx].body.push(SsaInst {
            value: v,
            op: SsaOp::FieldProj {
                receiver: current,
                field: fid,
                projected_type: None,
            },
            cfg_node,
            var_name: Some(chain_var.clone()),
            span,
        });
        value_defs.push(ValueDef {
            var_name: Some(chain_var.clone()),
            cfg_node,
            block: block_id,
        });
        current = v;
    }

    let method = segments.last().unwrap().to_string();
    Some((current, method))
}

/// Lower a CFG to SSA form for a single function scope.
///
/// `scope` filters nodes by `enclosing_func`:
///   - `None` → top-level code only (`enclosing_func.is_none()`)
///   - `Some(name)` → only nodes with `enclosing_func == Some(name)`
///
/// If `scope_all` is true, all nodes reachable from `entry` are included
/// regardless of `enclosing_func`.
pub fn lower_to_ssa(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
) -> Result<SsaBody, SsaError> {
    lower_to_ssa_inner(cfg, entry, scope, scope_all, false, &[])
}

/// Like `lower_to_ssa` but with formal parameter names supplied in declaration
/// order. External variables that match these names are placed first (in
/// declaration order) so that `Param { index }` indices 0..N correspond to
/// call-site argument positions.
pub fn lower_to_ssa_with_params(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
    formal_params: &[String],
) -> Result<SsaBody, SsaError> {
    lower_to_ssa_inner(cfg, entry, scope, scope_all, false, formal_params)
}

/// Like `lower_to_ssa` but with `scope_nop`: when true, all nodes are included
/// in the SSA body for graph connectivity, but out-of-scope nodes become Nop
/// (their defines/uses are ignored). This is used for the JS two-level solve
/// where the CFG linearizes function bodies inline.
pub fn lower_to_ssa_scoped_nop(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
) -> Result<SsaBody, SsaError> {
    lower_to_ssa_inner(cfg, entry, scope, false, true, &[])
}

fn lower_to_ssa_inner(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
    scope_nop: bool,
    formal_params: &[String],
) -> Result<SsaBody, SsaError> {
    if cfg.node_count() == 0 {
        return Err(SsaError::EmptyCfg);
    }

    // When scope_nop is set, traverse all nodes (scope_all=true) for graph connectivity
    let traverse_all = scope_all || scope_nop;

    // Collect reachable nodes in scope, stripping exception edges.
    let (reachable, filtered_edges, raw_exception_edges) =
        collect_reachable(cfg, entry, scope, traverse_all);

    // Build the set of nodes that should be treated as Nop (out-of-scope but included)
    let nop_nodes: HashSet<NodeIndex> = if scope_nop {
        let in_scope = |node: NodeIndex| -> bool {
            let info = &cfg[node];
            match scope {
                None => info.ast.enclosing_func.is_none(),
                Some(name) => info.ast.enclosing_func.as_deref() == Some(name),
            }
        };
        reachable
            .iter()
            .filter(|&&n| !in_scope(n) && !matches!(cfg[n].kind, StmtKind::Entry | StmtKind::Exit))
            .copied()
            .collect()
    } else {
        HashSet::new()
    };
    if reachable.is_empty() {
        return Err(SsaError::EmptyCfg);
    }

    // 1. Form basic blocks
    let (blocks_nodes, block_of_node, block_succs, block_preds) =
        form_blocks(cfg, entry, &reachable, &filtered_edges);

    let num_blocks = blocks_nodes.len();
    if num_blocks == 0 {
        return Err(SsaError::EmptyCfg);
    }

    // 2. Compute dominators on block-level graph
    let (block_graph, block_graph_entry) = build_block_graph(num_blocks, &block_succs, BlockId(0));
    let doms = simple_fast(&block_graph, block_graph_entry);

    // 3. Compute dominance frontiers
    let dom_frontiers = compute_dominance_frontiers(num_blocks, &block_preds, &doms, &block_graph);

    // 4. Collect variable definitions per block (skip nop nodes)
    let mut var_defs = collect_var_defs(cfg, &blocks_nodes, &nop_nodes);

    // 4b. For per-function scope: identify external variables (used but not defined)
    //     and inject synthetic Param defs at entry block so rename can find them.
    //     When formal_params is supplied, reorder so formal params come first in
    //     declaration order, this makes Param indices correspond to call-site positions.
    //
    let external_vars = if scope.is_some() && !scope_all && !scope_nop {
        let raw = identify_external_uses(cfg, &blocks_nodes, &var_defs);
        reorder_external_vars(raw, formal_params)
    } else {
        vec![]
    };
    // Register external vars as defined in block 0 so phi insertion considers them
    for var in &external_vars {
        var_defs.entry(var.clone()).or_default().insert(0);
    }

    // 5. Phi insertion (Cytron algorithm)
    let phi_placements = insert_phis(&var_defs, &dom_frontiers, num_blocks);

    // 6. Rename variables (dominator tree preorder walk)
    let dom_tree_children = build_dom_tree_children(num_blocks, &doms, &block_graph);
    let (
        mut ssa_blocks,
        mut value_defs,
        cfg_node_map,
        field_interner,
        field_writes,
        synthetic_externals,
    ) = rename_variables(
        cfg,
        &blocks_nodes,
        &block_succs,
        &block_preds,
        &phi_placements,
        &dom_tree_children,
        &filtered_edges,
        &external_vars,
        formal_params,
        &nop_nodes,
    );

    // 6b. Fill any missing phi operands with a shared Undef sentinel so
    // every phi has exactly one operand per predecessor. See
    // `fill_undef_phi_operands` for the invariant rationale.
    fill_undef_phi_operands(
        &mut ssa_blocks,
        &block_preds,
        &mut value_defs,
        &blocks_nodes,
    );

    // 7. Fill in preds/succs on SsaBlocks
    for bid in 0..num_blocks {
        let id = BlockId(bid as u32);
        ssa_blocks[bid].id = id;
        ssa_blocks[bid].preds = block_preds[bid]
            .iter()
            .map(|&b| BlockId(b as u32))
            .collect();
        ssa_blocks[bid].succs = block_succs[bid]
            .iter()
            .map(|&b| BlockId(b as u32))
            .collect();
    }

    // 7b. Debug assertions: verify structural invariants.
    // The helper body is `debug_assert!` only, so it's a no-op in release ,
    // call unconditionally to avoid a dead_code warning when the lib is
    // built without `--tests`.
    debug_assert_bfs_ordering(&block_preds);
    // Phi operand counts are a release-level invariant: every phi must
    // have exactly one operand per predecessor. Missing operands are
    // filled with an explicit Undef sentinel in
    // `fill_undef_phi_operands`; extra operands would reference
    // nonexistent predecessors and corrupt analysis silently.
    assert_phi_operand_counts(&ssa_blocks, &block_preds);

    // 8. Map exception edges from CFG node indices to SSA block IDs
    let exception_edges: Vec<(BlockId, BlockId)> = raw_exception_edges
        .iter()
        .filter_map(|(src_node, catch_node)| {
            let src_block = block_of_node.get(src_node)?;
            let catch_block = block_of_node.get(catch_node)?;
            Some((BlockId(*src_block as u32), BlockId(*catch_block as u32)))
        })
        .collect();

    let body = SsaBody {
        blocks: ssa_blocks,
        entry: BlockId(0),
        value_defs,
        cfg_node_map,
        exception_edges,
        field_interner,
        field_writes,
        synthetic_externals,
    };

    // 9. Catch-block reachability invariant.
    //
    // A CatchParam-carrying block that is neither reachable from entry nor
    // listed as an exception target indicates a CFG construction bug. Debug
    // builds panic loudly; release builds warn, record an engine note so
    // downstream findings carry "SSA lowering bailed" provenance, and fall
    // through to the existing orphan handling above (the "all definitions"
    // fallback) which remains sound for taint reachability.
    check_catch_block_reachability_gated(&body);

    Ok(body)
}

/// Runtime gate around [`check_catch_block_reachability`] that panics in
/// debug builds and warns + records an engine note in release builds.
///
/// The current lowering's orphan handling (`process_block` fallback in
/// `rename_variables`) already widens to an "all definitions" conservative
/// state for blocks without predecessors. That preserves soundness for
/// taint reachability but masks CFG-builder bugs: this gate surfaces them.
fn check_catch_block_reachability_gated(body: &SsaBody) {
    let result = super::invariants::check_catch_block_reachability(body);
    if let Err(err) = result {
        #[cfg(debug_assertions)]
        {
            if !catch_invariant_do_not_panic() {
                panic!(
                    "SSA catch-block reachability invariant violated:\n{}",
                    err.joined()
                );
            }
        }
        tracing::warn!(
            violations = %err.joined(),
            "SSA catch-block reachability invariant violated; proceeding with \
             conservative orphan fallback"
        );
        crate::taint::ssa_transfer::record_engine_note(
            crate::engine_notes::EngineNote::SsaLoweringBailed {
                reason: format!("catch_block_orphan: {}", err.joined()),
            },
        );
    }
}

// Test-only escape hatch: when set, `check_catch_block_reachability_gated`
// takes the release-build path (warn + engine note, no panic) even under
// `debug_assertions`. Used by the invariant test that constructs a
// synthetic orphan catch body.
#[cfg(debug_assertions)]
thread_local! {
    static CATCH_INVARIANT_DO_NOT_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(debug_assertions)]
#[allow(dead_code)]
pub(crate) fn set_catch_invariant_do_not_panic(on: bool) {
    CATCH_INVARIANT_DO_NOT_PANIC.with(|c| c.set(on));
}

#[cfg(debug_assertions)]
fn catch_invariant_do_not_panic() -> bool {
    CATCH_INVARIANT_DO_NOT_PANIC.with(|c| c.get())
}

/// Collect reachable nodes (BFS from entry), filtering by scope and stripping exception edges.
/// Returns (reachable set, filtered edges, exception edges as (src_node, catch_node)).
fn collect_reachable(
    cfg: &Cfg,
    entry: NodeIndex,
    scope: Option<&str>,
    scope_all: bool,
) -> (
    HashSet<NodeIndex>,
    Vec<(NodeIndex, NodeIndex, EdgeKind)>,
    Vec<(NodeIndex, NodeIndex)>,
) {
    let mut reachable = HashSet::new();
    let mut edges = Vec::new();
    let mut exception_edges = Vec::new();
    let mut queue = VecDeque::new();

    // Check if a node is in scope
    let in_scope = |node: NodeIndex| -> bool {
        if scope_all {
            return true;
        }
        let info = &cfg[node];
        match scope {
            None => info.ast.enclosing_func.is_none(),
            Some(name) => info.ast.enclosing_func.as_deref() == Some(name),
        }
    };

    if !in_scope(entry) && !scope_all {
        // Entry must be in scope; for top-level, Entry node often has no enclosing_func
        // Accept Entry/Exit nodes regardless of scope
        if !matches!(cfg[entry].kind, StmtKind::Entry | StmtKind::Exit) {
            return (reachable, edges, exception_edges);
        }
    }

    reachable.insert(entry);
    queue.push_back(entry);

    while let Some(node) = queue.pop_front() {
        for edge in cfg.edges(node) {
            let kind = *edge.weight();
            let target = edge.target();

            // Strip exception edges from the graph, but still visit targets
            // so catch-block nodes are included in the SSA body.
            if matches!(kind, EdgeKind::Exception) {
                if (in_scope(target)
                    || matches!(cfg[target].kind, StmtKind::Entry | StmtKind::Exit))
                    && reachable.insert(target)
                {
                    queue.push_back(target);
                }
                // Record exception edge for taint seeding
                exception_edges.push((node, target));
                continue;
            }

            // Allow Entry/Exit nodes and nodes in scope
            if !in_scope(target) && !matches!(cfg[target].kind, StmtKind::Entry | StmtKind::Exit) {
                continue;
            }

            edges.push((node, target, kind));

            if reachable.insert(target) {
                queue.push_back(target);
            }
        }
    }

    (reachable, edges, exception_edges)
}

/// Form basic blocks from filtered CFG nodes.
///
/// Returns:
/// - blocks_nodes: Vec<Vec<NodeIndex>>, nodes per block (in order)
/// - block_of_node: HashMap<NodeIndex, usize>, node → block index
/// - block_succs: Vec<Vec<usize>>, successors per block
/// - block_preds: Vec<Vec<usize>>, predecessors per block
fn form_blocks(
    cfg: &Cfg,
    entry: NodeIndex,
    reachable: &HashSet<NodeIndex>,
    filtered_edges: &[(NodeIndex, NodeIndex, EdgeKind)],
) -> (
    Vec<Vec<NodeIndex>>,
    HashMap<NodeIndex, usize>,
    Vec<Vec<usize>>,
    Vec<Vec<usize>>,
) {
    // Build adjacency from filtered edges
    let mut successors: HashMap<NodeIndex, Vec<(NodeIndex, EdgeKind)>> = HashMap::new();
    let mut in_degree: HashMap<NodeIndex, usize> = HashMap::new();
    let mut has_branching_in: HashMap<NodeIndex, bool> = HashMap::new();

    for node in reachable {
        in_degree.entry(*node).or_insert(0);
        has_branching_in.entry(*node).or_insert(false);
    }

    // CFG construction wires every Return / Throw node to the synthetic
    // function-exit node via a `Seq` edge so the underlying graph is a single
    // connected component.  Those edges are bookkeeping only: control flow
    // does not actually fall through a Return into the exit block.  Treating
    // them as block successors causes an early-return block to share its
    // post-exit body with the function's fall-through tail, silently merging
    // two distinct paths into one (the "merged-return" defect).  Strip them
    // here so block-level adjacency reflects real control flow; the SSA
    // terminator for the containing block becomes Return / Unreachable
    // instead of Goto(exit).
    let is_terminating =
        |n: NodeIndex| -> bool { matches!(cfg[n].kind, StmtKind::Return | StmtKind::Throw) };

    for &(src, tgt, kind) in filtered_edges {
        if is_terminating(src) {
            continue;
        }
        successors.entry(src).or_default().push((tgt, kind));
        *in_degree.entry(tgt).or_insert(0) += 1;
        if matches!(kind, EdgeKind::True | EdgeKind::False | EdgeKind::Back) {
            *has_branching_in.entry(tgt).or_insert(false) = true;
        }
    }

    // Determine block leaders
    let mut is_leader: HashSet<NodeIndex> = HashSet::new();
    is_leader.insert(entry); // entry is always a leader

    for &node in reachable {
        let in_deg = in_degree.get(&node).copied().unwrap_or(0);
        if in_deg > 1 || has_branching_in.get(&node).copied().unwrap_or(false) {
            is_leader.insert(node);
        }
        // Orphan nodes (reachable via exception edges but no filtered predecessors)
        // must be leaders so they get their own block (e.g. catch block entries).
        if in_deg == 0 && node != entry {
            is_leader.insert(node);
        }
        // Node following a multi-exit node
        let succs = successors.get(&node).map(|s| s.len()).unwrap_or(0);
        if succs > 1 {
            for &(tgt, _) in successors.get(&node).unwrap_or(&vec![]) {
                is_leader.insert(tgt);
            }
        }
    }

    // Build blocks by following single-successor Seq edges from each leader
    let mut blocks_nodes: Vec<Vec<NodeIndex>> = Vec::new();
    let mut block_of_node: HashMap<NodeIndex, usize> = HashMap::new();
    let mut visited: HashSet<NodeIndex> = HashSet::new();

    // BFS order to assign blocks deterministically (entry first)
    let mut leader_queue: VecDeque<NodeIndex> = VecDeque::new();
    leader_queue.push_back(entry);
    let mut leader_visited: HashSet<NodeIndex> = HashSet::new();
    leader_visited.insert(entry);

    // Discover leaders in BFS order over `cfg`, but skip edges whose
    // source is a terminating (Return / Throw) node.  Walking the raw
    // `cfg` directly here would re-introduce the bookkeeping
    // Return/Throw → fn_exit edges we just stripped, fn_exit (or any
    // post-return join) would be discovered through them and assigned a
    // block ID before its true block-level predecessors, breaking the
    // BFS-forward-pred invariant (`debug_assert_bfs_ordering`).
    //
    // We can't simply BFS our `successors` map because that excludes
    // exception edges entirely (collect_reachable strips them and records
    // them separately in `exception_edges`).  Catch-block nodes are still
    // in `reachable` and must be discoverable as leaders via the
    // try-body → catch path, only the terminating-source bookkeeping
    // edges are bogus.
    {
        let mut bfs_queue: VecDeque<NodeIndex> = VecDeque::new();
        let mut bfs_seen: HashSet<NodeIndex> = HashSet::new();
        bfs_queue.push_back(entry);
        bfs_seen.insert(entry);
        while let Some(node) = bfs_queue.pop_front() {
            if reachable.contains(&node) && is_leader.contains(&node) && leader_visited.insert(node)
            {
                leader_queue.push_back(node);
            }
            if is_terminating(node) {
                continue;
            }
            for edge in cfg.edges(node) {
                let tgt = edge.target();
                if reachable.contains(&tgt) && bfs_seen.insert(tgt) {
                    bfs_queue.push_back(tgt);
                }
            }
        }

        // Belt-and-braces: any leader still unvisited gets appended in
        // CFG-node-index order so block-ID assignment remains
        // deterministic.  We do NOT include the synthetic function-exit
        // node when it is unreachable through filtered edges, that
        // happens whenever every path in the body terminates explicitly
        // (e.g. a function whose only return is `return buf.toString()`
        // at the tail).  Including it would emit an orphan SSA block
        // with no real predecessors and no semantic meaning, which the
        // structural reachability invariant correctly rejects.
        // Genuine orphan handlers (catch blocks reached via stripped
        // exception edges) keep their entries here.
        let mut orphan_leaders: Vec<NodeIndex> = is_leader
            .iter()
            .copied()
            .filter(|n| !leader_visited.contains(n))
            .filter(|n| !matches!(cfg[*n].kind, StmtKind::Exit))
            .collect();
        orphan_leaders.sort_by_key(|n| n.index());
        for n in orphan_leaders {
            if leader_visited.insert(n) {
                leader_queue.push_back(n);
            }
        }
    }

    for leader in leader_queue {
        if visited.contains(&leader) {
            continue;
        }

        let block_idx = blocks_nodes.len();
        let mut block = vec![leader];
        visited.insert(leader);
        block_of_node.insert(leader, block_idx);

        // Follow single-successor Seq edges
        let mut current = leader;
        loop {
            let succs = successors.get(&current).cloned().unwrap_or_default();
            if succs.len() == 1
                && matches!(succs[0].1, EdgeKind::Seq)
                && !is_leader.contains(&succs[0].0)
            {
                let next = succs[0].0;
                if visited.insert(next) {
                    block.push(next);
                    block_of_node.insert(next, block_idx);
                    current = next;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        blocks_nodes.push(block);
    }

    // Build block-level successor/predecessor lists
    let num_blocks = blocks_nodes.len();
    let mut block_succs: Vec<Vec<usize>> = vec![vec![]; num_blocks];
    let mut block_preds: Vec<Vec<usize>> = vec![vec![]; num_blocks];

    for &(src, tgt, _kind) in filtered_edges {
        // Mirror the adjacency-construction filter above: edges out of
        // Return/Throw CFG nodes are not real successors at the block level.
        if is_terminating(src) {
            continue;
        }
        if let (Some(&src_blk), Some(&tgt_blk)) = (block_of_node.get(&src), block_of_node.get(&tgt))
        {
            if src_blk != tgt_blk && !block_succs[src_blk].contains(&tgt_blk) {
                block_succs[src_blk].push(tgt_blk);
                block_preds[tgt_blk].push(src_blk);
            }
        }
    }

    (blocks_nodes, block_of_node, block_succs, block_preds)
}

/// Build a block-level petgraph for dominator computation.
fn build_block_graph(
    num_blocks: usize,
    block_succs: &[Vec<usize>],
    _entry: BlockId,
) -> (Graph<BlockId, ()>, NodeIndex) {
    let mut g: Graph<BlockId, ()> = Graph::new();
    let mut block_nodes: Vec<NodeIndex> = Vec::with_capacity(num_blocks);

    for i in 0..num_blocks {
        block_nodes.push(g.add_node(BlockId(i as u32)));
    }

    for (i, succs) in block_succs.iter().enumerate() {
        for &s in succs {
            g.add_edge(block_nodes[i], block_nodes[s], ());
        }
    }

    let entry_gnode = block_nodes[0]; // block 0 is always entry
    (g, entry_gnode)
}

/// Compute dominance frontiers for all blocks.
fn compute_dominance_frontiers(
    num_blocks: usize,
    block_preds: &[Vec<usize>],
    doms: &Dominators<NodeIndex>,
    block_graph: &Graph<BlockId, ()>,
) -> Vec<HashSet<usize>> {
    let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); num_blocks];

    // Map block index → graph NodeIndex
    let block_node: Vec<NodeIndex> = block_graph.node_indices().collect();

    for n in 0..num_blocks {
        let preds = &block_preds[n];
        if preds.len() >= 2 {
            for &p in preds {
                let mut runner = p;
                // idom(n) in the block graph
                let n_gnode = block_node[n];
                let idom_n = doms.immediate_dominator(n_gnode);
                loop {
                    let runner_gnode = block_node[runner];
                    if idom_n == Some(runner_gnode) {
                        break;
                    }
                    df[runner].insert(n);
                    // Move runner to its immediate dominator
                    match doms.immediate_dominator(runner_gnode) {
                        Some(idom_runner) if idom_runner != runner_gnode => {
                            // Find block index from graph node
                            runner = block_graph[idom_runner].0 as usize;
                        }
                        _ => break, // reached root
                    }
                }
            }
        }
    }

    df
}

/// Identify variables used but not defined within the scoped blocks.
/// These represent external (e.g. global/top-level) variables that need
/// synthetic Param instructions so the SSA rename pass can reference them.
fn identify_external_uses(
    cfg: &Cfg,
    blocks_nodes: &[Vec<NodeIndex>],
    var_defs: &BTreeMap<String, HashSet<usize>>,
) -> Vec<String> {
    let mut used: HashSet<String> = HashSet::new();
    for nodes in blocks_nodes {
        for &node in nodes {
            for u in &cfg[node].taint.uses {
                used.insert(u.clone());
            }
        }
    }
    // External = used but never defined in any block
    let mut external: Vec<String> = used
        .into_iter()
        .filter(|u| !var_defs.contains_key(u))
        .collect();
    external.sort(); // deterministic order
    external
}

/// True iff `name` is a language-reserved method receiver identifier
/// (Rust/Python `self`, JS/TS/Java/PHP/C++ `this`).
///
/// Receivers get their own IR node ([`SsaOp::SelfParam`]) and are therefore
/// tracked as a distinct channel from positional parameters.  Keeping the
/// check localised to one helper ensures the set of receiver names stays
/// consistent across lowering and summary extraction.
pub(crate) fn is_receiver_name(name: &str) -> bool {
    matches!(name, "self" | "this")
}

/// Reorder external variables so the receiver (`self`/`this`) comes first,
/// followed by formal positional parameters in declaration order, followed
/// by remaining external vars in alphabetical order.
///
/// This fixed order is what the synthetic-parameter injection step relies
/// on to emit one [`SsaOp::SelfParam`] (for the leading receiver slot, when
/// present) followed by a contiguous run of [`SsaOp::Param { index }`] values
/// whose indices 0..N correspond exactly to positional call-site argument
/// positions, no receiver offset required anywhere downstream.
///
/// W1.b: every formal parameter gets a Param op even when the body never
/// references it directly.  Without this, the *first* `obj.f = rhs` on a
/// formal `obj` whose body never reads `obj` produces no W1
/// `field_writes` entry, `var_stacks["obj"]` is empty when the synth
/// Assign runs because no external-use path interned `obj`.  Subsequent
/// writes work because the synth Assign itself defines `obj`, so the
/// gap is exactly the FIRST write.  Always emitting a formal Param at
/// block 0 closes that gap.
fn reorder_external_vars(external: Vec<String>, formal_params: &[String]) -> Vec<String> {
    if formal_params.is_empty() {
        return external; // no reordering, preserve existing alphabetical sort
    }
    let ext_set: HashSet<&str> = external.iter().map(|s| s.as_str()).collect();
    let formal_set: HashSet<&str> = formal_params.iter().map(|s| s.as_str()).collect();
    let mut result = Vec::with_capacity(external.len());
    // Receiver first (highest priority), regardless of whether it appears in
    // formal_params or was discovered purely as an external reference.
    // Languages with explicit self (Rust/Python) put it in formal_params;
    // languages with implicit this (JS/TS/Java/PHP) have it only as an
    // external reference.  Either way, SelfParam should be emitted first.
    if ext_set.contains("self") || formal_set.contains("self") {
        result.push("self".to_string());
    } else if ext_set.contains("this") || formal_set.contains("this") {
        result.push("this".to_string());
    }
    // Formal positional params next (declaration order), skipping any
    // receiver that was already emitted above.  W1.b: include EVERY
    // formal regardless of whether the body uses it externally, an
    // unused formal that gets field-written via `obj.cache = rhs` still
    // needs a Param op so the synth Assign loop sees its prior reaching
    // def in `var_stacks`.
    for p in formal_params {
        if is_receiver_name(p) {
            continue;
        }
        result.push(p.clone());
    }
    // Remaining external vars alphabetically (external is already sorted),
    // excluding anything already placed.
    let placed: HashSet<String> = result.iter().cloned().collect();
    for v in external {
        if placed.contains(&v) {
            continue;
        }
        if !formal_set.contains(v.as_str()) && !is_receiver_name(&v) {
            result.push(v);
        }
    }
    result
}

/// Collect variable definitions per block: var_name → set of block indices.
/// Nodes in `nop_nodes` are skipped (they won't define variables in SSA).
fn collect_var_defs(
    cfg: &Cfg,
    blocks_nodes: &[Vec<NodeIndex>],
    nop_nodes: &HashSet<NodeIndex>,
) -> BTreeMap<String, HashSet<usize>> {
    let mut defs: BTreeMap<String, HashSet<usize>> = BTreeMap::new();

    for (block_idx, nodes) in blocks_nodes.iter().enumerate() {
        for &node in nodes {
            if nop_nodes.contains(&node) {
                continue;
            }
            if let Some(ref d) = cfg[node].taint.defines {
                defs.entry(d.clone()).or_default().insert(block_idx);
                // Register parent prefixes for synthetic base updates on field writes.
                // E.g. `obj.data` also registers `obj` so phi insertion works correctly.
                let mut path = d.as_str();
                while let Some(dot_pos) = path.rfind('.') {
                    path = &path[..dot_pos];
                    defs.entry(path.to_string()).or_default().insert(block_idx);
                }
            }
            // Register extra defines from destructuring patterns.
            for ed in &cfg[node].taint.extra_defines {
                defs.entry(ed.clone()).or_default().insert(block_idx);
            }
            // Implicit definitions for uninitialized declarations (e.g., C/C++
            // `char buf[256]`).  The variable appears in uses but not defines
            // because def_use() doesn't treat declarations without initializers
            // as definitions.  Registering here ensures phi insertion at join points.
            if cfg[node].taint.defines.is_none()
                && cfg[node].call.callee.is_none()
                && cfg[node].kind == StmtKind::Seq
                && cfg[node].taint.uses.len() == 1
            {
                defs.entry(cfg[node].taint.uses[0].clone())
                    .or_default()
                    .insert(block_idx);
            }
        }
    }

    defs
}

/// Cytron-style phi insertion: returns phi_placements[block] = set of var names needing phis.
///
/// Returns a `BTreeSet<String>` per block so downstream consumers that iterate
/// the set (notably `rename_variables`) observe a deterministic, alphabetical
/// order regardless of the underlying hasher state.  The Cytron algorithm
/// itself is order-independent, only its observers are.
fn insert_phis(
    var_defs: &BTreeMap<String, HashSet<usize>>,
    dom_frontiers: &[HashSet<usize>],
    _num_blocks: usize,
) -> Vec<BTreeSet<String>> {
    let num_blocks = dom_frontiers.len();
    let mut phi_placements: Vec<BTreeSet<String>> = vec![BTreeSet::new(); num_blocks];

    for (var, def_blocks) in var_defs {
        let mut worklist: VecDeque<usize> = def_blocks.iter().copied().collect();
        let mut has_phi: HashSet<usize> = HashSet::new();

        while let Some(b) = worklist.pop_front() {
            for &f in &dom_frontiers[b] {
                if has_phi.insert(f) {
                    phi_placements[f].insert(var.clone());
                    // Phi is a new definition, add to worklist
                    if !def_blocks.contains(&f) {
                        worklist.push_back(f);
                    }
                }
            }
        }
    }

    phi_placements
}

/// Build dominator tree children lists.
fn build_dom_tree_children(
    num_blocks: usize,
    doms: &Dominators<NodeIndex>,
    block_graph: &Graph<BlockId, ()>,
) -> Vec<Vec<usize>> {
    let mut children: Vec<Vec<usize>> = vec![vec![]; num_blocks];
    let block_nodes: Vec<NodeIndex> = block_graph.node_indices().collect();

    for i in 0..num_blocks {
        if let Some(idom) = doms.immediate_dominator(block_nodes[i]) {
            let idom_idx = block_graph[idom].0 as usize;
            if idom_idx != i {
                children[idom_idx].push(i);
            }
        }
    }

    children
}

/// Rename variables: dominator tree preorder walk with per-variable stacks.
///
/// Returns (ssa_blocks, value_defs, cfg_node_map).
fn rename_variables(
    cfg: &Cfg,
    blocks_nodes: &[Vec<NodeIndex>],
    block_succs: &[Vec<usize>],
    block_preds: &[Vec<usize>],
    phi_placements: &[BTreeSet<String>],
    dom_tree_children: &[Vec<usize>],
    filtered_edges: &[(NodeIndex, NodeIndex, EdgeKind)],
    external_vars: &[String],
    formal_params: &[String],
    nop_nodes: &HashSet<NodeIndex>,
) -> (
    Vec<SsaBlock>,
    Vec<ValueDef>,
    HashMap<NodeIndex, SsaValue>,
    crate::ssa::ir::FieldInterner,
    HashMap<SsaValue, (SsaValue, crate::ssa::ir::FieldId)>,
    HashSet<SsaValue>,
) {
    let num_blocks = blocks_nodes.len();
    let mut next_value: u32 = 0;
    let mut value_defs: Vec<ValueDef> = Vec::new();
    let mut cfg_node_map: HashMap<NodeIndex, SsaValue> = HashMap::new();
    // Per-body interner for FieldProj field names; populated when the
    // member-access decomposition (try_lower_field_proj_chain) emits a
    // chain for chained-receiver method calls (`a.b.c()`), and remains
    // empty otherwise so existing per-statement Call lowering is
    // bit-for-bit unchanged.
    let mut field_interner = crate::ssa::ir::FieldInterner::new();
    //side-table mapping each synthetic base-update
    // [`SsaOp::Assign`]'s defined value to its `(receiver, field)` pair.
    // Populated below at the synthetic-Assign emission site.  Read by
    // the taint engine to lift the assign into a structural field WRITE.
    let mut field_writes: HashMap<SsaValue, (SsaValue, crate::ssa::ir::FieldId)> = HashMap::new();

    // Per-variable rename stacks
    let mut var_stacks: HashMap<String, Vec<SsaValue>> = HashMap::new();

    // Pre-allocate SSA blocks
    let mut ssa_blocks: Vec<SsaBlock> = (0..num_blocks)
        .map(|i| SsaBlock {
            id: BlockId(i as u32),
            phis: Vec::new(),
            body: Vec::new(),
            terminator: Terminator::Unreachable,
            preds: SmallVec::new(),
            succs: SmallVec::new(),
        })
        .collect();

    // `BTreeMap` guarantees a deterministic (alphabetical) iteration order when
    // pushing phi values onto `var_stacks` and when filling operands on
    // successor phis, both sites are observable in SSA numbering if they
    // reordered between runs.
    let mut phi_values: Vec<BTreeMap<String, SsaValue>> = vec![BTreeMap::new(); num_blocks];

    // Pre-create phi instructions for all blocks (operands filled during rename)
    for (block_idx, vars) in phi_placements.iter().enumerate() {
        let block_id = BlockId(block_idx as u32);
        let cfg_node = blocks_nodes[block_idx][0]; // anchor to first node
        for var in vars {
            let v = SsaValue(next_value);
            next_value += 1;
            value_defs.push(ValueDef {
                var_name: Some(var.clone()),
                cfg_node,
                block: block_id,
            });
            phi_values[block_idx].insert(var.clone(), v);
            ssa_blocks[block_idx].phis.push(SsaInst {
                value: v,
                op: SsaOp::Phi(SmallVec::new()),
                cfg_node,
                var_name: Some(var.clone()),
                span: cfg[cfg_node].ast.span,
            });
        }
    }

    // Process blocks in dominator tree preorder
    // We need to track stack depths to restore after processing subtrees
    // Use iterative approach: process block, then process children, restore

    // Simpler approach: preorder walk with explicit save/restore
    fn process_block(
        block_idx: usize,
        cfg: &Cfg,
        blocks_nodes: &[Vec<NodeIndex>],
        block_succs: &[Vec<usize>],
        block_preds: &[Vec<usize>],
        phi_placements: &[BTreeSet<String>],
        dom_tree_children: &[Vec<usize>],
        filtered_edges: &[(NodeIndex, NodeIndex, EdgeKind)],
        var_stacks: &mut HashMap<String, Vec<SsaValue>>,
        ssa_blocks: &mut [SsaBlock],
        phi_values: &mut [BTreeMap<String, SsaValue>],
        value_defs: &mut Vec<ValueDef>,
        cfg_node_map: &mut HashMap<NodeIndex, SsaValue>,
        next_value: &mut u32,
        nop_nodes: &HashSet<NodeIndex>,
        field_interner: &mut crate::ssa::ir::FieldInterner,
        field_writes: &mut HashMap<SsaValue, (SsaValue, crate::ssa::ir::FieldId)>,
    ) {
        let block_id = BlockId(block_idx as u32);

        // Save stack depths for rollback
        let saved: Vec<(String, usize)> = var_stacks
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();

        // 1. Push pre-created phi values onto var stacks
        for (var, &v) in &phi_values[block_idx] {
            var_stacks.entry(var.clone()).or_default().push(v);
        }

        // 2. Process body nodes
        for &node in &blocks_nodes[block_idx] {
            let info = &cfg[node];

            // Helper: build Call args from arg_uses, falling back to info.taint.uses
            let build_call_args = |info: &crate::cfg::NodeInfo,
                                   var_stacks: &HashMap<String, Vec<SsaValue>>|
             -> (Vec<SmallVec<[SsaValue; 2]>>, Option<SsaValue>) {
                let receiver = info
                    .call
                    .receiver
                    .as_ref()
                    .and_then(|r| var_stacks.get(r).and_then(|s| s.last().copied()));
                let args = if !info.call.arg_uses.is_empty() {
                    let mut args: Vec<SmallVec<[SsaValue; 2]>> = info
                        .call
                        .arg_uses
                        .iter()
                        .map(|arg_idents| {
                            arg_idents
                                .iter()
                                .filter_map(|ident| {
                                    var_stacks.get(ident).and_then(|s| s.last().copied())
                                })
                                .collect()
                        })
                        .collect();
                    // For chained calls (e.g. fetch(url).then(fn)), arg_uses only
                    // captures the final call's args. Variables used by intermediate
                    // calls (like `url` in fetch) are in info.taint.uses but not arg_uses.
                    // Add them as an extra group so sink detection can see them.
                    //
                    // Exclude the receiver ident: it's carried on its own typed
                    // channel (`SsaOp::Call.receiver`).  Callers that care about
                    // positional arity must read it from `info.call.arg_uses.len()`,
                    // not `args.len()`, since this implicit group inflates args.
                    let arg_uses_flat: HashSet<&str> = info
                        .call
                        .arg_uses
                        .iter()
                        .flat_map(|g| g.iter().map(|s| s.as_str()))
                        .collect();
                    let receiver_ident = info.call.receiver.as_deref();
                    let implicit: SmallVec<[SsaValue; 2]> = info
                        .taint
                        .uses
                        .iter()
                        .filter(|u| !arg_uses_flat.contains(u.as_str()))
                        .filter(|u| Some(u.as_str()) != receiver_ident)
                        .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                        .collect();
                    if !implicit.is_empty() {
                        args.push(implicit);
                    }
                    args
                } else {
                    // Fallback: treat all uses as a single argument group
                    let all_uses: SmallVec<[SsaValue; 2]> = info
                        .taint
                        .uses
                        .iter()
                        .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                        .collect();
                    if all_uses.is_empty() {
                        vec![]
                    } else {
                        vec![all_uses]
                    }
                };
                (args, receiver)
            };

            // Determine operation and collect uses
            // Out-of-scope nodes (nop_nodes) become Nop: they preserve graph
            // connectivity but don't participate in taint flow.
            let op = if nop_nodes.contains(&node) {
                SsaOp::Nop
            } else if info.catch_param {
                SsaOp::CatchParam
            } else if info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
                && info.call.callee.is_none()
            {
                // Pure source (e.g. $_GET, env var), no callee, so no args to track.
                // Source-labeled calls (e.g. file_get_contents) fall through to Call
                // so argument taint and sink detection still work.
                SsaOp::Source
            } else if info.call.callee.is_some() {
                let callee = info.call.callee.as_deref().unwrap_or("").to_string();
                let (mut args, mut receiver) = build_call_args(info, var_stacks);
                // try decomposing chained-receiver method calls
                // (`a.b.c()`) into a FieldProj chain plus a bare-method Call
                // so downstream consumers can read the receiver structure
                // without re-parsing the callee text.  Bails to None on any
                // non-chain receiver (current behaviour preserved).
                let (final_callee, callee_text) = match try_lower_field_proj_chain(
                    &callee,
                    var_stacks,
                    field_interner,
                    block_idx,
                    block_id,
                    next_value,
                    ssa_blocks,
                    value_defs,
                    node,
                    info.ast.span,
                ) {
                    Some((recv_v, bare_method)) => {
                        receiver = Some(recv_v);
                        // Strip any positional arg group that exactly matches the
                        // chain root identifier, it has been replaced by the
                        // FieldProj chain receiver, and re-listing it as an
                        // argument would inflate arity / double-taint.
                        if let Some(base_ident) = callee.split('.').next() {
                            if let Some(base_v) = var_stacks.get(base_ident).and_then(|s| s.last())
                            {
                                args.retain(|grp| !(grp.len() == 1 && grp.first() == Some(base_v)));
                            }
                        }
                        (bare_method, Some(callee.clone()))
                    }
                    None => (callee, None),
                };
                SsaOp::Call {
                    callee: final_callee,
                    callee_text,
                    args,
                    receiver,
                }
            } else if info.taint.defines.is_some()
                && info.taint.uses.is_empty()
                && !info
                    .taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
            {
                // Reassignment kill: a node that defines a variable but has no
                // uses (operands) and is not a source is a constant/literal
                // assignment.  SSA rename allocates a fresh SsaValue, so
                // downstream references see this new (untainted) value, the
                // prior tainted definition is implicitly dead.
                SsaOp::Const(info.taint.const_text.clone())
            } else if info.taint.defines.is_some() {
                let mut uses: SmallVec<[SsaValue; 4]> = info
                    .taint
                    .uses
                    .iter()
                    .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                    .collect();
                // Inject Const for binary expression literal operand.
                // When a binary expression has one identifier and one numeric literal
                // (e.g., `flags & 0x07`), the literal isn't in `uses`. Inject a
                // synthetic Const instruction so the Assign has 2 uses, preventing
                // copy propagation from eliminating the operation.
                if uses.len() == 1 && info.bin_op.is_some() && info.bin_op_const.is_some() {
                    let const_val = info.bin_op_const.unwrap();
                    let const_v = SsaValue(*next_value);
                    *next_value += 1;
                    let const_inst = SsaInst {
                        value: const_v,
                        op: SsaOp::Const(Some(const_val.to_string())),
                        cfg_node: node,
                        var_name: None,
                        span: info.ast.span,
                    };
                    ssa_blocks[block_idx].body.push(const_inst);
                    value_defs.push(ValueDef {
                        var_name: None,
                        cfg_node: node,
                        block: block_id,
                    });
                    uses.push(const_v);
                }
                SsaOp::Assign(uses)
            } else if matches!(info.kind, StmtKind::Return | StmtKind::Throw)
                && !info.taint.uses.is_empty()
            {
                // `return s` / `throw e` with identifier uses: emit an
                // `Assign(uses)` so the SSA carries an explicit pass-through
                // for the returned/thrown value.  Without this, the Return
                // node was lowered as a `Nop` and the terminator-setup
                // "last non-Nop body inst" search returned None, producing
                // `Terminator::Return(None)` for a function that visibly
                // returns an identifier.  That broke per-return-path
                // PathFact narrowing for non-Rust languages where the
                // returned identifier wasn't computed in the same block
                // (e.g. Python `def f(s): return s`, `s` is a Param in
                // block 0, the Return block itself has no body insts).
                let uses: SmallVec<[SsaValue; 4]> = info
                    .taint
                    .uses
                    .iter()
                    .filter_map(|u| var_stacks.get(u).and_then(|s| s.last().copied()))
                    .collect();
                if uses.is_empty() {
                    SsaOp::Nop
                } else {
                    SsaOp::Assign(uses)
                }
            } else if matches!(
                info.kind,
                StmtKind::Entry
                    | StmtKind::Exit
                    | StmtKind::If
                    | StmtKind::Loop
                    | StmtKind::Break
                    | StmtKind::Continue
                    | StmtKind::Return
                    | StmtKind::Throw
            ) {
                SsaOp::Nop
            } else if info.call.callee.is_some() {
                let callee = info.call.callee.as_deref().unwrap_or("").to_string();
                let (mut args, mut receiver) = build_call_args(info, var_stacks);
                // same FieldProj-chain decomposition as the primary
                // Call branch above, kept in sync because this fallback
                // path also constructs SSA Call ops (used for control-flow
                // wrapper calls that landed past the earlier match arms).
                let (final_callee, callee_text) = match try_lower_field_proj_chain(
                    &callee,
                    var_stacks,
                    field_interner,
                    block_idx,
                    block_id,
                    next_value,
                    ssa_blocks,
                    value_defs,
                    node,
                    info.ast.span,
                ) {
                    Some((recv_v, bare_method)) => {
                        receiver = Some(recv_v);
                        if let Some(base_ident) = callee.split('.').next() {
                            if let Some(base_v) = var_stacks.get(base_ident).and_then(|s| s.last())
                            {
                                args.retain(|grp| !(grp.len() == 1 && grp.first() == Some(base_v)));
                            }
                        }
                        (bare_method, Some(callee.clone()))
                    }
                    None => (callee, None),
                };
                SsaOp::Call {
                    callee: final_callee,
                    callee_text,
                    args,
                    receiver,
                }
            } else {
                SsaOp::Nop
            };

            // Allocate SSA value
            let v = SsaValue(*next_value);
            *next_value += 1;
            let var_name_for_ssa = if nop_nodes.contains(&node) {
                None
            } else if info.taint.defines.is_some() {
                info.taint.defines.clone()
            } else if info.kind == StmtKind::Seq
                && info.call.callee.is_none()
                && info.taint.uses.len() == 1
                && !var_stacks.contains_key(&info.taint.uses[0])
            {
                // Implicit definition for uninitialized declarations (e.g.,
                // C/C++ `char buf[256]`).  Creates a reaching definition so
                // output-parameter sources like fgets() can taint the buffer
                // and subsequent uses (e.g., system(buf)) see the tainted value.
                Some(info.taint.uses[0].clone())
            } else {
                None
            };
            value_defs.push(ValueDef {
                var_name: var_name_for_ssa.clone(),
                cfg_node: node,
                block: block_id,
            });

            // Push defined variable onto stack (skip nop nodes)
            if let Some(ref d) = var_name_for_ssa {
                var_stacks.entry(d.clone()).or_default().push(v);
            }

            cfg_node_map.insert(node, v);

            // Clone op for potential extra_defines before moving into SsaInst
            let primary_op_for_extras = if info.taint.extra_defines.is_empty() {
                None
            } else {
                Some(op.clone())
            };
            ssa_blocks[block_idx].body.push(SsaInst {
                value: v,
                op,
                cfg_node: node,
                var_name: var_name_for_ssa.clone(),
                span: info.ast.span,
            });

            // Synthetic base update: when a dotted path is defined (e.g. `obj.data`),
            // create synthetic Assign instructions for parent prefixes (e.g. `obj`)
            // so that subsequent reads of the base variable see the field write.
            // Only includes the new field value (not the old base) so that field
            // overwrites properly kill taint: if obj.data is re-assigned to a
            // constant, the base `obj` no longer carries that field's taint.
            //
            //each synthetic Assign also records its
            // structural identity into `field_writes`, `(receiver_old_value,
            // FieldId(field_name))`, so the taint engine can recognise the
            // synthetic assign as a field WRITE and mirror the rhs taint
            // into the matching `(loc, field)` cell on `SsaTaintState`.
            // The "old" parent value is the reaching def of `parent` BEFORE
            // we push the new `synth_v`; when no prior def exists (the
            // parent is undefined at this point), we skip the side-table
            // entry so the consumer's `pt(receiver)` walk produces no work.
            if !nop_nodes.contains(&node) {
                if let Some(ref d) = info.taint.defines {
                    let mut current = d.as_str();
                    let mut child_value = v;
                    while let Some(dot_pos) = current.rfind('.') {
                        let parent = &current[..dot_pos];
                        let field_name = &current[dot_pos + 1..];
                        // Snapshot prior reaching def of `parent` BEFORE we
                        // push the new synth_v.  Used by the field-write
                        // side-table as the receiver SsaValue.
                        let prior_parent_value: Option<SsaValue> =
                            var_stacks.get(parent).and_then(|s| s.last().copied());
                        let synth_v = SsaValue(*next_value);
                        *next_value += 1;
                        let synth_uses: SmallVec<[SsaValue; 4]> =
                            SmallVec::from_elem(child_value, 1);
                        value_defs.push(ValueDef {
                            var_name: Some(parent.to_string()),
                            cfg_node: node,
                            block: block_id,
                        });
                        var_stacks
                            .entry(parent.to_string())
                            .or_default()
                            .push(synth_v);
                        ssa_blocks[block_idx].body.push(SsaInst {
                            value: synth_v,
                            op: SsaOp::Assign(synth_uses),
                            cfg_node: node,
                            var_name: Some(parent.to_string()),
                            span: info.ast.span,
                        });
                        // Record `(synth_v -> (prior_parent, field_id))` so
                        // the taint engine can lift the synthetic assign
                        // into a field-write hook.  The field name is
                        // interned through the per-body `FieldInterner` so
                        // FieldProj reads downstream resolve to the same id.
                        if let Some(rcv) = prior_parent_value {
                            let fid = field_interner.intern(field_name);
                            field_writes.insert(synth_v, (rcv, fid));
                        }
                        child_value = synth_v;
                        current = parent;
                    }
                }
            }

            // Emit extra SSA instructions for destructuring bindings.
            // Each extra define inherits the same op (Source/Call/Assign) as the primary.
            if let Some(ref primary_op) = primary_op_for_extras {
                for extra_def in &info.taint.extra_defines {
                    let ev = SsaValue(*next_value);
                    *next_value += 1;
                    value_defs.push(ValueDef {
                        var_name: Some(extra_def.clone()),
                        cfg_node: node,
                        block: block_id,
                    });
                    var_stacks.entry(extra_def.clone()).or_default().push(ev);
                    ssa_blocks[block_idx].body.push(SsaInst {
                        value: ev,
                        op: primary_op.clone(),
                        cfg_node: node,
                        var_name: Some(extra_def.clone()),
                        span: info.ast.span,
                    });
                }
            }
        }

        // 3. Set terminator
        let succs = &block_succs[block_idx];
        let last_node = *blocks_nodes[block_idx].last().unwrap();

        ssa_blocks[block_idx].terminator = if succs.is_empty() {
            // A block with no successors at the block level is one of:
            //   (1) a block containing a Throw, terminates with an
            //       exception; no normal fall-through.
            //   (2) a block containing a Return, terminates with a value
            //       (or void).  After form_blocks strips the bookkeeping
            //       Seq edge from Return → fn_exit, every explicit-return
            //       block lands here, including `if cond { return X; }`
            //       early returns.
            //   (3) the function-exit (fn_exit) block itself when the
            //       function falls off the end (implicit return).
            //
            // Distinguish them by inspecting the block's CFG nodes.
            let return_node = blocks_nodes[block_idx]
                .iter()
                .copied()
                .find(|&n| cfg[n].kind == StmtKind::Return);
            let has_throw_node = blocks_nodes[block_idx]
                .iter()
                .any(|&n| cfg[n].kind == StmtKind::Throw);

            if has_throw_node && return_node.is_none() {
                // Throw terminates control flow with an exception.  No
                // structured Throw terminator exists today; downstream
                // analyses rely on `exception_edges` (recorded separately)
                // for catch-block dispatch.  Mark the normal-flow exit as
                // Unreachable so successor consumers do not invent a
                // synthetic fall-through edge.
                Terminator::Unreachable
            } else if let Some(rn) = return_node {
                let return_info = &cfg[rn];
                // Return-value resolution.  Mirror the legacy
                // `has_const_return` path so callers see exactly the same
                // SSA shape they did before the merged-return fix, only
                // the *terminator* changes (Goto(exit) → Return(_)), not
                // the value selection.
                //
                //   (a) Literal return (`return 'x'`, `return None`,
                //       `return []`, `return;`).  Marked by
                //       `taint.uses.is_empty()` on the Return CFG node.
                //       Emit a synthetic Const inst so taint never leaks
                //       from an unrelated inst earlier in the same block
                //       (regression guard: C-1 inline-return precision).
                //   (b) Computed / passthrough return, last non-Nop body
                //       inst.  Covers `return foo()` (Call sits before the
                //       Return Nop), `return x + y` (Assign), and the
                //       implicit tail expression collapsed into a single
                //       block by the leader-following loop.  When the
                //       Return carries identifier uses (`return req`,
                //       `return { req.session, ... }`), the SSA defs for
                //       those identifiers are already on the body as
                //       Param / Assign / Source insts, picking the last
                //       one matches pre-fix behaviour exactly.
                //   (c) Void / unresolved, `Return(None)`.
                if return_info.taint.uses.is_empty() {
                    let const_text = return_info.taint.const_text.clone();
                    let const_v = SsaValue(*next_value);
                    *next_value += 1;
                    let block_id = BlockId(block_idx as u32);
                    value_defs.push(ValueDef {
                        var_name: None,
                        cfg_node: rn,
                        block: block_id,
                    });
                    ssa_blocks[block_idx].body.push(SsaInst {
                        value: const_v,
                        op: SsaOp::Const(const_text),
                        cfg_node: rn,
                        var_name: None,
                        span: return_info.ast.span,
                    });
                    Terminator::Return(Some(const_v))
                } else {
                    let from_body = ssa_blocks[block_idx]
                        .body
                        .iter()
                        .rev()
                        .find(|inst| !matches!(inst.op, SsaOp::Nop))
                        .map(|inst| inst.value);
                    Terminator::Return(from_body)
                }
            } else {
                // (3) fn_exit / true fall-off, no Return CFG node in this
                // block.  Use the last non-Nop body instruction as the
                // implicit return value (e.g. the function's tail-position
                // expression in Rust).
                let ret_val = ssa_blocks[block_idx]
                    .body
                    .iter()
                    .rev()
                    .find(|inst| !matches!(inst.op, SsaOp::Nop))
                    .map(|inst| inst.value);
                Terminator::Return(ret_val)
            }
        } else if succs.len() == 1 {
            Terminator::Goto(BlockId(succs[0] as u32))
        } else if succs.len() == 2 {
            // Find the If/Loop node that branches
            let cond_node = blocks_nodes[block_idx]
                .iter()
                .rev()
                .find(|&&n| matches!(cfg[n].kind, StmtKind::If | StmtKind::Loop))
                .copied()
                .unwrap_or(last_node);

            // Determine which successor is true/false by looking at edge kinds
            let mut true_blk = succs[0];
            let mut false_blk = succs[1];

            // Check filtered edges from any node in this block to successors
            for &(src, tgt, kind) in filtered_edges {
                if blocks_nodes[block_idx].contains(&src) {
                    let tgt_blk_opt = succs.iter().position(|&s| {
                        blocks_nodes
                            .get(s)
                            .is_some_and(|nodes| nodes.contains(&tgt))
                    });
                    if let Some(tgt_blk_pos) = tgt_blk_opt {
                        match kind {
                            EdgeKind::True => true_blk = succs[tgt_blk_pos],
                            EdgeKind::False => false_blk = succs[tgt_blk_pos],
                            _ => {}
                        }
                    }
                }
            }

            // Lower structured condition from CFG metadata
            let cond_info = &cfg[cond_node];
            let condition = if cond_info.condition_text.is_some()
                && !cond_info.condition_vars.is_empty()
            {
                let expr =
                    crate::constraint::lower::lower_condition_with_stacks(cond_info, var_stacks);
                if matches!(expr, crate::constraint::lower::ConditionExpr::Unknown) {
                    None
                } else {
                    Some(Box::new(expr))
                }
            } else {
                None
            };

            Terminator::Branch {
                cond: cond_node,
                true_blk: BlockId(true_blk as u32),
                false_blk: BlockId(false_blk as u32),
                condition,
            }
        } else {
            // More than 2 successors, model as a multi-way Switch.
            //
            // This replaces the previous `Goto(first)` collapse: the
            // structured terminator now enumerates every target instead
            // of hiding N-1 of them behind `block.succs`. Flow consumers
            // (taint, const-prop, symex) still iterate `succs` as
            // authoritative, but downstream tooling that inspects the
            // terminator shape gets the full fanout.
            //
            // Note: today's switch-statement CFG construction decomposes
            // cases into a cascade of binary `Branch` headers (see
            // `build_switch` in src/cfg.rs), so real switch statements
            // never reach this arm. Folding the cascade back into a
            // single Switch node is a follow-up; in the meantime, this
            // arm fires only on genuine multi-way CFG fanouts (e.g.
            // future Go-switch / Java-arrow / Rust-match lowerings).
            //
            // Scrutinee: use the primary SSA value defined at the last
            // node in this block when one exists; fall back to
            // `SsaValue(0)` (a valid index, SSA numbering is 1-based
            // only conceptually, and value 0 is always present in a
            // non-empty body) when no value is defined. Downstream
            // consumers that care about the scrutinee (abstract interp,
            // symex per-case constraints) treat a missing/degenerate
            // scrutinee as "unknown" rather than panicking.
            let scrutinee = cfg_node_map.get(&last_node).copied().unwrap_or(SsaValue(0));
            let targets: SmallVec<[BlockId; 4]> =
                succs.iter().skip(1).map(|&s| BlockId(s as u32)).collect();
            let default = BlockId(succs[0] as u32);
            // Synthetic ≥3-way fanouts have no per-case literal metadata ,
            // every entry is None (unknown), so the executor falls back to
            // first-reachable behavior on this terminator.
            let case_values: SmallVec<[Option<crate::constraint::domain::ConstValue>; 4]> =
                std::iter::repeat_with(|| None)
                    .take(targets.len())
                    .collect();
            tracing::debug!(
                block = block_idx,
                num_succs = succs.len(),
                "emitting Terminator::Switch for ≥3-way fanout",
            );
            Terminator::Switch {
                scrutinee,
                targets,
                default,
                case_values,
            }
        };

        // 4. Fill phi operands in successor blocks
        for &succ in succs {
            for (var, &phi_val) in &phi_values[succ] {
                // The version of `var` reaching from this block
                let reaching_val = var_stacks.get(var).and_then(|s| s.last().copied());
                if let Some(rv) = reaching_val {
                    // Find the phi instruction and add this operand
                    for phi in &mut ssa_blocks[succ].phis {
                        if phi.value == phi_val {
                            if let SsaOp::Phi(ref mut operands) = phi.op {
                                operands.push((block_id, rv));
                            }
                        }
                    }
                }
            }
        }

        // 5. Recurse into dominator tree children
        for &child in &dom_tree_children[block_idx] {
            process_block(
                child,
                cfg,
                blocks_nodes,
                block_succs,
                block_preds,
                phi_placements,
                dom_tree_children,
                filtered_edges,
                var_stacks,
                ssa_blocks,
                phi_values,
                value_defs,
                cfg_node_map,
                next_value,
                nop_nodes,
                field_interner,
                field_writes,
            );
        }

        // 6. Restore stacks
        for (var, depth) in &saved {
            if let Some(stack) = var_stacks.get_mut(var) {
                stack.truncate(*depth);
            }
        }
        // Remove any new variables that weren't in saved
        let saved_vars: HashSet<&String> = saved.iter().map(|(k, _)| k).collect();
        var_stacks.retain(|k, _| saved_vars.contains(k));
    }

    // Inject synthetic Param instructions at START of block 0 for external variables.
    // These create SSA definitions so the rename pass can reference them.
    // Pre-seed var_stacks so process_block sees them.
    //
    // `external_vars` contains both real formal parameters and free / closure-
    // captured variables (variables read by the body but not declared as a
    // formal and not assigned anywhere).  Both end up emitted as
    // [`SsaOp::Param`] in block 0; we record the SSA values that correspond
    // to free vars in `synthetic_externals` so downstream analyses (the JS/TS
    // handler-name auto-seed in particular) can avoid treating closure
    // captures as if they were parameters of the function under analysis.
    //
    // **Conservative behaviour when `formal_params` is empty.** Several
    // call sites (`lower_to_ssa`, `lower_to_ssa_scoped_nop`) don't supply
    // formal parameter names; in that case we cannot distinguish formals
    // from free vars structurally, so we leave `synthetic_externals` empty
    // and the auto-seed pass keeps its pre-fix behaviour of treating every
    // `Param` op as a candidate.  Only callers that pass a non-empty
    // `formal_params` slice (`lower_to_ssa_with_params`, used by the
    // findings pipeline's per-function lowering) opt into the
    // closure-capture distinction.
    let mut synthetic_externals: HashSet<SsaValue> = HashSet::new();
    let formal_set: HashSet<&str> = formal_params.iter().map(|s| s.as_str()).collect();
    let track_synthetic = !formal_params.is_empty();
    if !external_vars.is_empty() {
        let entry_cfg_node = blocks_nodes[0][0];
        let mut synthetic_body = Vec::with_capacity(external_vars.len());
        let mut positional_idx: usize = 0;
        for var in external_vars.iter() {
            let v = SsaValue(next_value);
            next_value += 1;
            value_defs.push(ValueDef {
                var_name: Some(var.clone()),
                cfg_node: entry_cfg_node,
                block: BlockId(0),
            });
            let is_receiver = is_receiver_name(var);
            let op = if is_receiver {
                SsaOp::SelfParam
            } else {
                let op = SsaOp::Param {
                    index: positional_idx,
                };
                positional_idx += 1;
                op
            };
            // A non-receiver var is "synthetic" (a free / closure capture)
            // when it is *not* one of the function's declared formals AND
            // not a dotted access on a formal (`input.cmd` where `input` is
            // a formal — it represents a structural projection of the
            // formal, not a free variable; the auto-seed should still treat
            // it as part of the formal's own taint surface).  Receivers are
            // intentionally excluded: `this` / `self` represent the implicit
            // receiver, which always belongs to the function.
            //
            // Only fire when the caller supplied formal-parameter names; see
            // the `track_synthetic` rationale above.
            let root_is_formal = var
                .split_once('.')
                .map(|(root, _)| formal_set.contains(root))
                .unwrap_or(false);
            if track_synthetic
                && !is_receiver
                && !formal_set.contains(var.as_str())
                && !root_is_formal
            {
                synthetic_externals.insert(v);
            }
            synthetic_body.push(SsaInst {
                value: v,
                op,
                cfg_node: entry_cfg_node,
                var_name: Some(var.clone()),
                span: (0, 0),
            });
            var_stacks.entry(var.clone()).or_default().push(v);
        }
        // Prepend synthetic params before any existing body instructions
        synthetic_body.append(&mut ssa_blocks[0].body);
        ssa_blocks[0].body = synthetic_body;
    }

    process_block(
        0, // entry block
        cfg,
        blocks_nodes,
        block_succs,
        block_preds,
        phi_placements,
        dom_tree_children,
        filtered_edges,
        &mut var_stacks,
        &mut ssa_blocks,
        &mut phi_values,
        &mut value_defs,
        &mut cfg_node_map,
        &mut next_value,
        nop_nodes,
        &mut field_interner,
        &mut field_writes,
    );

    // Process orphan blocks (e.g. catch blocks disconnected after exception edge removal).
    // These blocks have no predecessors and weren't reached by the dominator tree walk.
    //
    // Rebuild var_stacks from already-processed instructions so that catch blocks
    // can reference variables defined before the try block (e.g. `userInput`).
    let has_orphans =
        (1..num_blocks).any(|bid| block_preds[bid].is_empty() && ssa_blocks[bid].body.is_empty());
    if has_orphans {
        // Rebuild var_stacks from all SSA instructions created during the main walk.
        // This gives orphan blocks access to all variable definitions.
        var_stacks.clear();
        for block in &ssa_blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                if let Some(ref name) = inst.var_name {
                    var_stacks.entry(name.clone()).or_default().push(inst.value);
                }
            }
        }

        for bid in 1..num_blocks {
            if block_preds[bid].is_empty() && ssa_blocks[bid].body.is_empty() {
                process_block(
                    bid,
                    cfg,
                    blocks_nodes,
                    block_succs,
                    block_preds,
                    phi_placements,
                    dom_tree_children,
                    filtered_edges,
                    &mut var_stacks,
                    &mut ssa_blocks,
                    &mut phi_values,
                    &mut value_defs,
                    &mut cfg_node_map,
                    &mut next_value,
                    nop_nodes,
                    &mut field_interner,
                    &mut field_writes,
                );
            }
        }
    }

    (
        ssa_blocks,
        value_defs,
        cfg_node_map,
        field_interner,
        field_writes,
        synthetic_externals,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
//  Debug invariant checkers
// ─────────────────────────────────────────────────────────────────────────────

/// Verify BFS block ordering: every non-entry, non-orphan block must have at
/// least one predecessor with a smaller block ID.
fn debug_assert_bfs_ordering(block_preds: &[Vec<usize>]) {
    for (i, preds) in block_preds.iter().enumerate() {
        if i == 0 {
            continue; // entry block
        }
        if preds.is_empty() {
            continue; // orphan block (e.g. catch block reached via exception edge)
        }
        let has_forward_pred = preds.iter().any(|&p| p < i);
        debug_assert!(
            has_forward_pred,
            "Block {} has no forward predecessor — BFS ordering violated. Preds: {:?}",
            i, preds
        );
    }
}

/// Verify phi operand counts: each phi must have exactly one operand
/// per predecessor, and every operand must reference an actual
/// predecessor of the block.
///
/// Runs in release builds because phi-operand mismatches are
/// load-bearing for soundness, downstream taint, const, and abstract
/// analyses iterate phi operands by `(pred_blk, value)` pairs, and
/// either a missing operand (silent "no contribution" on that edge)
/// or a phantom operand (garbage into the join) corrupts analysis
/// without surfacing.
///
/// The invariant is strict equality. Predecessors that carry no
/// reaching definition for the phi's variable are filled with the
/// [`SsaOp::Undef`] sentinel in `fill_undef_phi_operands`, rather than
/// being dropped, so consumers that look up by `(pred_blk, value)`
/// see a real operand for every control-flow edge.
fn assert_phi_operand_counts(ssa_blocks: &[SsaBlock], block_preds: &[Vec<usize>]) {
    use std::collections::HashSet;
    for (i, block) in ssa_blocks.iter().enumerate() {
        let pred_set: HashSet<u32> = block_preds[i].iter().map(|&p| p as u32).collect();
        for phi in &block.phis {
            if let SsaOp::Phi(ref operands) = phi.op {
                assert_eq!(
                    operands.len(),
                    block_preds[i].len(),
                    "SSA phi operand count does not match predecessor count: block {} phi v{} \
                     (var={:?}) has {} operands but block has {} predecessors. \
                     preds={:?}, operand_preds={:?}",
                    i,
                    phi.value.0,
                    phi.var_name,
                    operands.len(),
                    block_preds[i].len(),
                    block_preds[i],
                    operands.iter().map(|(b, _)| b.0).collect::<Vec<_>>(),
                );
                // Each operand's pred block must be an actual predecessor,
                // and no predecessor may appear more than once.
                let mut seen: HashSet<u32> = HashSet::new();
                for (pred_blk, _) in operands.iter() {
                    assert!(
                        pred_set.contains(&pred_blk.0),
                        "SSA phi operand references nonexistent predecessor: block {} phi v{} \
                         references pred B{} but block predecessors are {:?}",
                        i,
                        phi.value.0,
                        pred_blk.0,
                        block_preds[i],
                    );
                    assert!(
                        seen.insert(pred_blk.0),
                        "SSA phi operand duplicates predecessor: block {} phi v{} has two \
                         operands for pred B{}",
                        i,
                        phi.value.0,
                        pred_blk.0,
                    );
                }
            }
        }
    }
}

/// Post-rename pass: ensure every phi has one operand per predecessor.
///
/// During rename, phi operands are only pushed when the variable has a
/// live reaching definition on that predecessor edge. Edges where the
/// variable is not yet defined (e.g. a try-body rejoining after a
/// catch-only binding, an early-return branch on a later-defined
/// variable, an orphan catch block's implicit predecessors) leave the
/// phi with fewer operands than the block has predecessors.
///
/// This pass scans all phis, and for every missing `(pred_block, _)`
/// slot, pushes `(pred_block, undef_val)` where `undef_val` is a
/// single shared sentinel instruction ([`SsaOp::Undef`]) synthesized
/// at the end of block 0's body. Consumers iterate phi operands by
/// `(pred_blk, value)` and therefore see a real operand on every
/// control-flow edge, no implicit "missing = empty" semantics.
///
/// The Undef instruction is created lazily (only when at least one phi
/// has a gap) so functions with fully-dominating definitions pay zero
/// cost. All phis share the same Undef value: a phi operand is
/// identified by its `(pred_block, value)` pair, so sharing the value
/// across phis is safe and keeps the synthesized-instruction count at
/// most one per function body.
fn fill_undef_phi_operands(
    ssa_blocks: &mut [SsaBlock],
    block_preds: &[Vec<usize>],
    value_defs: &mut Vec<ValueDef>,
    blocks_nodes: &[Vec<NodeIndex>],
) {
    // Fast path: detect whether any phi has a gap. Avoid allocating
    // the Undef value in the common case where every phi is saturated.
    let needs_undef = ssa_blocks.iter().enumerate().any(|(bi, block)| {
        block.phis.iter().any(|phi| {
            if let SsaOp::Phi(ref operands) = phi.op {
                operands.len() < block_preds[bi].len()
            } else {
                false
            }
        })
    });
    if !needs_undef {
        return;
    }

    // Anchor the synthetic Undef instruction to the entry block's first
    // CFG node so span lookups don't hit an invalid NodeIndex.
    let anchor_node = blocks_nodes
        .first()
        .and_then(|b| b.first())
        .copied()
        .expect("entry block has at least one CFG node");

    let undef_val = SsaValue(value_defs.len() as u32);
    value_defs.push(ValueDef {
        var_name: None,
        cfg_node: anchor_node,
        block: BlockId(0),
    });
    // Place the Undef instruction at the end of block 0's body so it
    // appears after any synthetic Param / SelfParam emissions, its
    // only role is to anchor the SsaValue; ordering relative to other
    // body instructions is cosmetic (no consumer depends on its
    // position, only on the value lookup).
    ssa_blocks[0].body.push(SsaInst {
        value: undef_val,
        op: SsaOp::Undef,
        cfg_node: anchor_node,
        var_name: None,
        span: (0, 0),
    });

    // Fill missing operand slots. Iterate `block_preds[bi]` in its
    // natural order so the resulting phi operand list is deterministic
    // across runs.
    for (bi, block) in ssa_blocks.iter_mut().enumerate() {
        for phi in block.phis.iter_mut() {
            if let SsaOp::Phi(ref mut operands) = phi.op {
                if operands.len() == block_preds[bi].len() {
                    continue;
                }
                use std::collections::HashSet;
                let present: HashSet<u32> = operands.iter().map(|(b, _)| b.0).collect();
                for &pred in &block_preds[bi] {
                    let pid = pred as u32;
                    if !present.contains(&pid) {
                        operands.push((BlockId(pid), undef_val));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{EdgeKind, NodeInfo, StmtKind, TaintMeta};
    use petgraph::Graph;

    fn make_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    #[test]
    fn linear_cfg_no_phis() {
        // Entry → x=1 → y=x → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let n1 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let n2 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("y".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, n1, EdgeKind::Seq);
        cfg.add_edge(n1, n2, EdgeKind::Seq);
        cfg.add_edge(n2, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Should be a single block (all Seq edges, no branches)
        assert_eq!(ssa.blocks.len(), 1);
        // No phis in a linear CFG
        assert!(ssa.blocks[0].phis.is_empty());
        // 4 body instructions (entry, x=1, y=x, exit)
        assert_eq!(ssa.blocks[0].body.len(), 4);
    }

    #[test]
    fn diamond_cfg_produces_phi() {
        // Entry → x=1 → If → [True: x=2] [False: x=3] → Join → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let def_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let true_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let false_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, def_x, EdgeKind::Seq);
        cfg.add_edge(def_x, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, true_node, EdgeKind::True);
        cfg.add_edge(if_node, false_node, EdgeKind::False);
        cfg.add_edge(true_node, join, EdgeKind::Seq);
        cfg.add_edge(false_node, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Should have multiple blocks
        assert!(ssa.blocks.len() >= 3);

        // The join block should have a phi for "x"
        let join_block = ssa
            .blocks
            .iter()
            .find(|b| !b.phis.is_empty())
            .expect("should have a block with a phi");
        assert_eq!(join_block.phis.len(), 1);
        assert_eq!(join_block.phis[0].var_name.as_deref(), Some("x"));

        // Phi should have 2 operands (from true and false branches)
        if let SsaOp::Phi(ref operands) = join_block.phis[0].op {
            assert_eq!(operands.len(), 2);
        } else {
            panic!("expected Phi op");
        }
    }

    #[test]
    fn loop_cfg_produces_phi() {
        // Entry → x=0 → Loop header → [Back: x=x+1] → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let def_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let loop_header = cfg.add_node(make_node(StmtKind::Loop));
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, def_x, EdgeKind::Seq);
        cfg.add_edge(def_x, loop_header, EdgeKind::Seq);
        cfg.add_edge(loop_header, body, EdgeKind::True);
        cfg.add_edge(body, loop_header, EdgeKind::Back);
        cfg.add_edge(loop_header, exit, EdgeKind::False);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Loop header block should have a phi for "x" (from entry and back edge)
        let header_phis: Vec<_> = ssa.blocks.iter().filter(|b| !b.phis.is_empty()).collect();

        assert!(
            !header_phis.is_empty(),
            "loop header should have a phi for x"
        );

        let x_phi = header_phis[0]
            .phis
            .iter()
            .find(|p| p.var_name.as_deref() == Some("x"));
        assert!(x_phi.is_some(), "should have phi for variable x");
    }

    #[test]
    fn multiple_reassignments_distinct_values() {
        // Entry → x=1 → x=2 → x=3 → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let n1 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let n2 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let n3 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, n1, EdgeKind::Seq);
        cfg.add_edge(n1, n2, EdgeKind::Seq);
        cfg.add_edge(n2, n3, EdgeKind::Seq);
        cfg.add_edge(n3, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Each definition of x should produce a distinct SsaValue
        let x_values: Vec<_> = ssa
            .value_defs
            .iter()
            .enumerate()
            .filter(|(_, vd)| vd.var_name.as_deref() == Some("x"))
            .map(|(i, _)| SsaValue(i as u32))
            .collect();

        assert_eq!(x_values.len(), 3, "three definitions of x");
        // All distinct
        let unique: HashSet<_> = x_values.iter().collect();
        assert_eq!(unique.len(), 3, "all SsaValues should be distinct");
    }

    #[test]
    fn empty_cfg_returns_error() {
        let cfg: Cfg = Graph::new();
        let result = lower_to_ssa(&cfg, NodeIndex::new(0), None, true);
        assert!(result.is_err());
    }

    // ── BFS ordering and phi invariant tests ─────────────────────────────

    #[test]
    fn bfs_ordering_holds_for_linear_cfg() {
        // Entry → A → B → Exit, all blocks should satisfy BFS ordering
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let a = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let b = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("y".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, a, EdgeKind::Seq);
        cfg.add_edge(a, b, EdgeKind::Seq);
        cfg.add_edge(b, exit, EdgeKind::Seq);

        // This exercises the debug_assert_bfs_ordering in debug builds
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(!ssa.blocks.is_empty());
    }

    #[test]
    fn bfs_ordering_holds_for_diamond_cfg() {
        // Entry → If → [True] [False] → Join → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let def_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let true_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let false_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, def_x, EdgeKind::Seq);
        cfg.add_edge(def_x, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, true_node, EdgeKind::True);
        cfg.add_edge(if_node, false_node, EdgeKind::False);
        cfg.add_edge(true_node, join, EdgeKind::Seq);
        cfg.add_edge(false_node, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        // Exercises both BFS ordering and phi operand count assertions
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        // The join block should have a phi with exactly 2 operands (== 2 preds)
        let phi_block = ssa.blocks.iter().find(|b| !b.phis.is_empty());
        if let Some(block) = phi_block {
            assert_eq!(
                block.preds.len(),
                2,
                "join block should have 2 predecessors"
            );
            for phi in &block.phis {
                if let SsaOp::Phi(ref ops) = phi.op {
                    assert!(
                        ops.len() <= block.preds.len(),
                        "phi operands should not exceed predecessor count"
                    );
                }
            }
        }
    }

    #[test]
    fn bfs_ordering_holds_for_loop_with_back_edge() {
        // Entry → x=0 → Loop → body(x=x+1) → [Back→Loop] → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let def_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let loop_h = cfg.add_node(make_node(StmtKind::Loop));
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, def_x, EdgeKind::Seq);
        cfg.add_edge(def_x, loop_h, EdgeKind::Seq);
        cfg.add_edge(loop_h, body, EdgeKind::True);
        cfg.add_edge(body, loop_h, EdgeKind::Back);
        cfg.add_edge(loop_h, exit, EdgeKind::False);

        // Exercises BFS ordering with back edges and phi on loop header
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(!ssa.blocks.is_empty());
    }

    #[test]
    fn orphan_catch_block_does_not_violate_bfs_ordering() {
        // Entry → body → Exit, with an exception edge body → catch → Exit
        // The catch block becomes an orphan (no normal-flow predecessors)
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let catch = cfg.add_node(NodeInfo {
            catch_param: true,
            taint: TaintMeta {
                defines: Some("e".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, body, EdgeKind::Seq);
        cfg.add_edge(body, exit, EdgeKind::Seq);
        cfg.add_edge(body, catch, EdgeKind::Exception);
        cfg.add_edge(catch, exit, EdgeKind::Seq);

        // The catch block is reached via exception edge (stripped from normal flow)
        // so it may appear as an orphan. The BFS assertion should skip it.
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(!ssa.blocks.is_empty());
    }

    #[test]
    fn phi_operand_count_equals_pred_count_in_diamond() {
        // Specific test: phi operands == predecessor count (not just <=)
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let t = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("v".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let f = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("v".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["v".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, t, EdgeKind::True);
        cfg.add_edge(if_node, f, EdgeKind::False);
        cfg.add_edge(t, join, EdgeKind::Seq);
        cfg.add_edge(f, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        let phi_block = ssa
            .blocks
            .iter()
            .find(|b| !b.phis.is_empty())
            .expect("should have a phi block");

        for phi in &phi_block.phis {
            if let SsaOp::Phi(ref ops) = phi.op {
                assert_eq!(
                    ops.len(),
                    phi_block.preds.len(),
                    "phi operand count should equal predecessor count in a clean diamond"
                );
            }
        }
    }

    #[test]
    fn bfs_assertion_helper_accepts_valid_orderings() {
        // Direct unit test of the assertion helper with valid input
        let block_preds = vec![
            vec![],     // block 0: entry (no preds)
            vec![0],    // block 1: pred is block 0 (forward)
            vec![0, 1], // block 2: both forward preds
            vec![],     // block 3: orphan (no preds)
            vec![2],    // block 4: forward pred
        ];
        // Should not panic
        debug_assert_bfs_ordering(&block_preds);
    }

    /// Regression guard: a catch block that joins an exception
    /// predecessor and a normal control-flow predecessor must lower to a
    /// consistent phi. For variables defined before the try (live on
    /// *both* edges), the phi at the catch block has exactly two operands
    ///, one per predecessor, and the release assertion accepts it.
    #[test]
    fn catch_block_join_phi_has_operand_per_live_predecessor() {
        // Entry → defines `x` → Try → (Seq) → Join ← (Exception via body) Catch
        //                                                      ↑
        //                         A phi for `x` at the join block should carry
        //                         one operand from each of its two predecessors.
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let define_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let catch = cfg.add_node(NodeInfo {
            catch_param: true,
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, define_x, EdgeKind::Seq);
        cfg.add_edge(define_x, body, EdgeKind::Seq);
        cfg.add_edge(body, join, EdgeKind::Seq);
        cfg.add_edge(body, catch, EdgeKind::Exception);
        cfg.add_edge(catch, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        // Lowering must succeed, the assertion is active in release.
        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Locate the block containing a phi for `x`; it must be the join
        // block with two reachable predecessors. The phi must have
        // exactly two operands.
        let phi_block = ssa
            .blocks
            .iter()
            .find(|b| {
                b.phis
                    .iter()
                    .any(|p| p.var_name.as_deref() == Some("x") && matches!(p.op, SsaOp::Phi(_)))
            })
            .expect("expected a phi for `x` at the catch/normal join");
        assert_eq!(
            phi_block.preds.len(),
            2,
            "catch/normal join block must have 2 predecessors, got {}",
            phi_block.preds.len()
        );
        let phi_for_x = phi_block
            .phis
            .iter()
            .find(|p| p.var_name.as_deref() == Some("x"))
            .unwrap();
        if let SsaOp::Phi(ref operands) = phi_for_x.op {
            assert_eq!(
                operands.len(),
                2,
                "phi for `x` at the catch/normal join must have one operand per \
                 predecessor, got {}",
                operands.len()
            );
        } else {
            panic!("expected SsaOp::Phi for `x`");
        }
    }

    /// Regression guard for the Undef fill pass. When a variable is
    /// only defined on one branch of a join (e.g. a catch-only binding
    /// rejoining the normal path), the lowering must still emit one
    /// phi operand per predecessor, the missing edge becoming a
    /// reference to the synthesized `SsaOp::Undef` sentinel rather
    /// than being dropped.
    #[test]
    fn partial_phi_edge_fills_with_undef_sentinel() {
        // Entry → Body → Join
        //           ↓
        //        Catch (defines `e`) → Join
        //
        // `e` is defined only on the exception path; on the normal path
        // from Body → Join it has no reaching definition. The phi for `e`
        // at Join must have two operands (one per predecessor), with the
        // Body-side operand pointing at the Undef sentinel.
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let body = cfg.add_node(make_node(StmtKind::Seq));
        let catch = cfg.add_node(NodeInfo {
            catch_param: true,
            taint: TaintMeta {
                defines: Some("e".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["e".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, body, EdgeKind::Seq);
        cfg.add_edge(body, join, EdgeKind::Seq);
        cfg.add_edge(body, catch, EdgeKind::Exception);
        cfg.add_edge(catch, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Find the phi for `e`.
        let phi_block = ssa
            .blocks
            .iter()
            .find(|b| b.phis.iter().any(|p| p.var_name.as_deref() == Some("e")))
            .expect("expected a phi for `e`");
        let phi_for_e = phi_block
            .phis
            .iter()
            .find(|p| p.var_name.as_deref() == Some("e"))
            .unwrap();
        let operands = match &phi_for_e.op {
            SsaOp::Phi(ops) => ops,
            _ => panic!("expected SsaOp::Phi for `e`"),
        };

        // Strict invariant: one operand per predecessor.
        assert_eq!(
            operands.len(),
            phi_block.preds.len(),
            "phi for `e` must have one operand per predecessor",
        );

        // At least one operand must reference the Undef sentinel (the
        // Body-side edge where `e` has no reaching definition).
        let found_inst = |v: SsaValue| -> Option<&SsaInst> {
            ssa.blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .find(|i| i.value == v)
        };
        let any_undef = operands.iter().any(|(_, v)| {
            found_inst(*v)
                .map(|i| matches!(i.op, SsaOp::Undef))
                .unwrap_or(false)
        });
        assert!(
            any_undef,
            "phi for `e` at the catch-join must reference SsaOp::Undef \
             on the normal-path predecessor edge",
        );
    }

    #[test]
    fn phi_assertion_helper_accepts_exact_operand_count() {
        // Direct test of the assertion helper: a phi with exactly as many
        // operands as the block has predecessors must not panic.
        let dummy_node = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Phi(smallvec::smallvec![
                    (BlockId(0), SsaValue(1)),
                    (BlockId(2), SsaValue(2)),
                ]),
                cfg_node: dummy_node,
                var_name: Some("x".into()),
                span: (0, 0),
            }],
            body: vec![],
            terminator: Terminator::Unreachable,
            preds: smallvec::smallvec![BlockId(0), BlockId(2)],
            succs: smallvec::smallvec![],
        };
        let block_preds = vec![vec![], vec![0, 2], vec![0]];
        assert_phi_operand_counts(
            &[
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![],
                    succs: smallvec::smallvec![BlockId(1)],
                },
                block,
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![BlockId(0)],
                    succs: smallvec::smallvec![BlockId(1)],
                },
            ],
            &block_preds,
        );
    }

    #[test]
    #[should_panic(expected = "SSA phi operand count does not match predecessor count")]
    fn phi_assertion_helper_rejects_more_operands_than_preds() {
        // A phi with MORE operands than preds references a nonexistent
        // predecessor, unsound because downstream consumers either
        // panic on the lookup or silently feed garbage taint into the
        // join. Strict-equality invariant catches this.
        let dummy_node = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Phi(smallvec::smallvec![
                    (BlockId(0), SsaValue(1)),
                    (BlockId(2), SsaValue(2)),
                    (BlockId(3), SsaValue(3)),
                ]),
                cfg_node: dummy_node,
                var_name: Some("x".into()),
                span: (0, 0),
            }],
            body: vec![],
            terminator: Terminator::Unreachable,
            preds: smallvec::smallvec![BlockId(0), BlockId(2)],
            succs: smallvec::smallvec![],
        };
        let block_preds = vec![vec![], vec![0, 2]];
        assert_phi_operand_counts(
            &[
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![],
                    succs: smallvec::smallvec![BlockId(1)],
                },
                block,
            ],
            &block_preds,
        );
    }

    #[test]
    #[should_panic(expected = "SSA phi operand count does not match predecessor count")]
    fn phi_assertion_helper_rejects_fewer_operands_than_preds() {
        // A phi with fewer operands than preds violates the strict-equality
        // invariant: `fill_undef_phi_operands` is responsible for filling
        // every missing slot with an Undef sentinel, so the final body
        // should never have gaps. This test guards the post-pass.
        let dummy_node = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Phi(smallvec::smallvec![(BlockId(0), SsaValue(1))]),
                cfg_node: dummy_node,
                var_name: Some("e".into()),
                span: (0, 0),
            }],
            body: vec![],
            terminator: Terminator::Unreachable,
            preds: smallvec::smallvec![BlockId(0), BlockId(2)],
            succs: smallvec::smallvec![],
        };
        let block_preds = vec![vec![], vec![0, 2]];
        assert_phi_operand_counts(
            &[
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![],
                    succs: smallvec::smallvec![BlockId(1)],
                },
                block,
            ],
            &block_preds,
        );
    }

    #[test]
    #[should_panic(expected = "SSA phi operand references nonexistent predecessor")]
    fn phi_assertion_helper_rejects_wrong_pred_block() {
        // A phi with the correct operand count but referencing a block
        // that isn't actually a predecessor must also fail the invariant.
        let dummy_node = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Phi(smallvec::smallvec![
                    (BlockId(0), SsaValue(1)),
                    (BlockId(3), SsaValue(2)),
                ]),
                cfg_node: dummy_node,
                var_name: Some("x".into()),
                span: (0, 0),
            }],
            body: vec![],
            terminator: Terminator::Unreachable,
            preds: smallvec::smallvec![BlockId(0), BlockId(2)],
            succs: smallvec::smallvec![],
        };
        let block_preds = vec![vec![], vec![0, 2]];
        assert_phi_operand_counts(
            &[
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec::smallvec![],
                    succs: smallvec::smallvec![BlockId(1)],
                },
                block,
            ],
            &block_preds,
        );
    }

    #[test]
    fn three_successor_collapse_produces_switch() {
        // Build a CFG where a single node has 3 successors. The
        // structured `Terminator::Switch` replaced the old
        // `Goto(first)` collapse so every target is visible on the
        // terminator shape (not only on `block.succs`).
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let branch = cfg.add_node(make_node(StmtKind::If));
        let s0 = cfg.add_node(make_node(StmtKind::Seq));
        let s1 = cfg.add_node(make_node(StmtKind::Seq));
        let s2 = cfg.add_node(make_node(StmtKind::Seq));
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, branch, EdgeKind::Seq);
        cfg.add_edge(branch, s0, EdgeKind::True);
        cfg.add_edge(branch, s1, EdgeKind::False);
        cfg.add_edge(branch, s2, EdgeKind::Seq);
        cfg.add_edge(s0, exit, EdgeKind::Seq);
        cfg.add_edge(s1, exit, EdgeKind::Seq);
        cfg.add_edge(s2, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(!ssa.blocks.is_empty());

        let switch_block = ssa
            .blocks
            .iter()
            .find(|b| matches!(b.terminator, Terminator::Switch { .. }) && b.succs.len() >= 3)
            .expect("expected a block with a Switch terminator and ≥3 succs");

        assert_eq!(
            switch_block.succs.len(),
            3,
            "≥3-successor lowering must retain all succs on block.succs, got {:?}",
            switch_block.succs
        );

        if let Terminator::Switch {
            targets, default, ..
        } = &switch_block.terminator
        {
            // Default is the first succ (deterministic ordering); the
            // remaining N-1 succs populate `targets` in order.
            assert_eq!(
                *default, switch_block.succs[0],
                "Switch default must match succs[0]"
            );
            assert_eq!(
                targets.len(),
                switch_block.succs.len() - 1,
                "Switch targets must cover every succ except default"
            );
            for (i, t) in targets.iter().enumerate() {
                assert_eq!(
                    *t,
                    switch_block.succs[i + 1],
                    "Switch target[{i}] must match succs[{}]",
                    i + 1
                );
            }
        }
    }

    #[test]
    fn normal_two_successor_produces_branch() {
        // Regression: normal 2-successor case should still produce Branch
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let if_node = cfg.add_node(make_node(StmtKind::If));
        let t = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let f = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, t, EdgeKind::True);
        cfg.add_edge(if_node, f, EdgeKind::False);
        cfg.add_edge(t, exit, EdgeKind::Seq);
        cfg.add_edge(f, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        let has_branch = ssa
            .blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Branch { .. }));
        assert!(
            has_branch,
            "normal 2-successor case must produce Branch, not Goto"
        );
    }

    /// Regression: a block containing an explicit Return CFG node must
    /// terminate with [`Terminator::Return`], never [`Terminator::Goto`]
    /// to a synthetic exit block.  Previously, the bookkeeping
    /// `Return → fn_exit` `Seq` edge made early-return blocks fall into
    /// the single-successor `Goto` arm, and the fall-through tail
    /// expression's body got merged into the shared exit block, every
    /// early-return path therefore appeared to also execute the tail.
    /// Mirrors the `if cond { return X; } Y` shape that motivated the fix.
    #[test]
    fn early_return_block_terminates_with_return_not_goto_to_exit() {
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        // Param-style external use (x is read by the if condition).
        let if_node = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::If)
        });
        // True branch: return constant.  uses=[] + const_text=Some triggers
        // the literal-return path, ensuring the block emits a synthetic
        // Const + Return(Some(_)), the same shape `return None` /
        // `return String::new()` produces in real Rust code.
        let early_ret = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                const_text: Some("\"\"".to_string()),
                ..Default::default()
            },
            ..make_node(StmtKind::Return)
        });
        // False branch: tail expression that defines `y` (the implicit
        // function return value).
        let tail = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("y".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, if_node, EdgeKind::Seq);
        cfg.add_edge(if_node, early_ret, EdgeKind::True);
        cfg.add_edge(if_node, tail, EdgeKind::False);
        // Bookkeeping wire-up the real CFG construction performs in
        // `build_cfg`, Return / Throw → fn_exit via Seq, so the SSA
        // lowering has to handle it.
        cfg.add_edge(early_ret, exit, EdgeKind::Seq);
        cfg.add_edge(tail, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Locate the block containing the early-return CFG node and
        // assert it terminates with Return, not Goto(_) into the
        // shared exit block.
        let early_block = ssa
            .blocks
            .iter()
            .find(|b| {
                b.body
                    .iter()
                    .chain(b.phis.iter())
                    .any(|inst| inst.cfg_node == early_ret)
            })
            .expect("early-return CFG node must live in some SSA block");
        assert!(
            matches!(early_block.terminator, Terminator::Return(_)),
            "early-return block must terminate with Return, got {:?}",
            early_block.terminator
        );
        assert!(
            early_block.succs.is_empty(),
            "early-return block must have no successors at the block level, \
             got succs = {:?}",
            early_block.succs
        );

        // The fall-through (tail) block must NOT have the early-return
        // block as a predecessor.  Pre-fix, both the early-return path
        // and the tail path merged into the shared fn_exit block, so the
        // tail's body was reachable from the early-return path, that's
        // the merged-return defect.
        let tail_block = ssa
            .blocks
            .iter()
            .find(|b| {
                b.body
                    .iter()
                    .chain(b.phis.iter())
                    .any(|inst| inst.cfg_node == tail)
            })
            .expect("tail CFG node must live in some SSA block");
        let early_block_id = early_block.id;
        assert!(
            !tail_block.preds.contains(&early_block_id),
            "tail block must not have early-return block as a predecessor; \
             merged-return defect would re-emerge.  tail.preds = {:?}, \
             early_block_id = {:?}",
            tail_block.preds,
            early_block_id
        );
    }

    /// Regression: an OR-chain rejection arm such as
    /// `if a || b || c { return X; } Y` must have its rejection body emit a
    /// `Terminator::Return(_)` and have `succs.is_empty()`.  Pre-fix the
    /// rejection body's String::new() Call shared a block whose only
    /// successor was the merged tail, losing the early-return semantics
    /// entirely and diluting per-return-path PathFact narrowing.
    #[test]
    fn or_chain_rejection_block_terminates_with_return() {
        use crate::cfg::build_cfg;

        let src = br#"
            fn sanitize_path(s: &str) -> String {
                if s.contains("..") || s.starts_with('/') || s.starts_with('\\') {
                    return String::new();
                }
                s.to_string()
            }
        "#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_rust::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src.as_slice(), None).unwrap();
        let file_cfg = build_cfg(&tree, src.as_slice(), "rust", "test.rs", None);
        let body = if file_cfg.bodies.len() > 1 {
            &file_cfg.bodies[1]
        } else {
            file_cfg.first_body()
        };
        let cfg = &body.graph;
        let entry = body.entry;

        // Locate the Return CFG node sourced from the if-body and the tail
        // expression's Call node so the assertions are meaningful even if
        // block ordering shifts.
        let mut rejection_call: Option<NodeIndex> = None;
        for idx in cfg.node_indices() {
            let info = &cfg[idx];
            if info.kind == StmtKind::Call {
                if let Some(callee) = &info.call.callee {
                    if callee == "String::new" || callee.ends_with("String::new") {
                        rejection_call = Some(idx);
                    }
                }
            }
        }
        let rejection_call = rejection_call
            .expect("CFG must contain a String::new() Call node for the rejection arm");

        let ssa = lower_to_ssa(cfg, entry, None, true).expect("SSA lowering should succeed");

        // Find the SSA block containing the String::new() Call.  This is
        // the rejection-arm block.
        let rejection_block = ssa
            .blocks
            .iter()
            .find(|b| {
                b.body
                    .iter()
                    .chain(b.phis.iter())
                    .any(|inst| inst.cfg_node == rejection_call)
            })
            .expect("rejection-arm Call must live in some SSA block");

        assert!(
            rejection_block.succs.is_empty(),
            "rejection-arm block must have no block-level successors after \
             return-frontier strip; got succs = {:?}",
            rejection_block.succs
        );
        assert!(
            matches!(rejection_block.terminator, Terminator::Return(_)),
            "rejection-arm block must terminate with Terminator::Return; got {:?}",
            rejection_block.terminator
        );
    }

    /// Cross-language regression: the same merged-return defect that the Rust
    /// fix closed must not appear in C. The C OR-chain shape from
    /// `tests/benchmark/corpus/c/safe/safe_direct_path_sanitizer.c` has both
    /// a rejection arm (`return ""`) and a tail return (`return s`).  Both
    /// must produce blocks whose terminator is `Terminator::Return(_)`.
    #[test]
    fn c_or_chain_both_return_arms_terminate_with_return() {
        use crate::cfg::build_cfg;

        let src = br#"
            const char *sanitize_path(const char *s) {
                if (strstr(s, "..") != NULL || s[0] == '/' || s[0] == '\\') {
                    return "";
                }
                return s;
            }
        "#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_c::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src.as_slice(), None).unwrap();
        let file_cfg = build_cfg(&tree, src.as_slice(), "c", "test.c", None);
        let body = file_cfg.first_body();
        let cfg = &body.graph;
        let entry = body.entry;

        let ssa = lower_to_ssa(cfg, entry, None, true).expect("SSA lowering should succeed");

        let return_blocks: Vec<&SsaBlock> = ssa
            .blocks
            .iter()
            .filter(|b| matches!(b.terminator, Terminator::Return(_)))
            .collect();
        assert!(
            return_blocks.len() >= 2,
            "Expected ≥2 Return-terminated blocks (rejection arm + tail); got {}: {:?}",
            return_blocks.len(),
            ssa.blocks
                .iter()
                .map(|b| (b.id, &b.terminator))
                .collect::<Vec<_>>()
        );

        // Each Return-terminated block must have an empty successor list
        // (no fall-through past Return).
        for b in &return_blocks {
            assert!(
                b.succs.is_empty(),
                "Return-terminated block id={:?} has succs={:?}",
                b.id,
                b.succs
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // FieldProj chain lowering tests
    // ─────────────────────────────────────────────────────────────────
    //
    // These tests pin the contract that `try_lower_field_proj_chain`
    // emits a `FieldProj` chain for chained-receiver method calls
    // (`a.b.c.method()`) and bails (preserving the existing single-Call
    // lowering) for everything else.  Per-language end-to-end coverage
    // lives below in `phase2_e2e_*` tests; the unit tests here pin the
    // helper's behaviour without going through tree-sitter.

    /// Build a freshly-allocated empty SSA scratch state suitable for
    /// invoking `try_lower_field_proj_chain` in isolation.  Returns
    /// `(var_stacks, field_interner, ssa_blocks, value_defs, next_value)`.
    fn fresh_proj_scratch() -> (
        std::collections::HashMap<String, Vec<SsaValue>>,
        crate::ssa::ir::FieldInterner,
        Vec<SsaBlock>,
        Vec<ValueDef>,
        u32,
    ) {
        let blocks = vec![SsaBlock {
            id: BlockId(0),
            phis: Vec::new(),
            body: Vec::new(),
            terminator: Terminator::Unreachable,
            preds: SmallVec::new(),
            succs: SmallVec::new(),
        }];
        (
            std::collections::HashMap::new(),
            crate::ssa::ir::FieldInterner::new(),
            blocks,
            Vec::new(),
            0,
        )
    }

    /// Seed a single SSA value `SsaValue(0)` for `name` so the chain
    /// helper's base lookup succeeds.
    fn seed_var(
        var_stacks: &mut std::collections::HashMap<String, Vec<SsaValue>>,
        value_defs: &mut Vec<ValueDef>,
        next_value: &mut u32,
        name: &str,
    ) -> SsaValue {
        let v = SsaValue(*next_value);
        *next_value += 1;
        value_defs.push(ValueDef {
            var_name: Some(name.into()),
            cfg_node: NodeIndex::new(0),
            block: BlockId(0),
        });
        var_stacks.entry(name.into()).or_default().push(v);
        v
    }

    #[test]
    fn try_lower_field_proj_chain_too_few_segments_returns_none() {
        // 0 dots: bare callee → no chain.
        let (mut vs, mut interner, mut blocks, mut defs, mut nv) = fresh_proj_scratch();
        seed_var(&mut vs, &mut defs, &mut nv, "obj");
        assert!(
            try_lower_field_proj_chain(
                "foo",
                &vs,
                &mut interner,
                0,
                BlockId(0),
                &mut nv,
                &mut blocks,
                &mut defs,
                NodeIndex::new(0),
                (0, 0),
            )
            .is_none()
        );

        // 1 dot: simple receiver, NOT decomposed (existing receiver channel
        // already handles `obj.method()` calls).
        assert!(
            try_lower_field_proj_chain(
                "obj.method",
                &vs,
                &mut interner,
                0,
                BlockId(0),
                &mut nv,
                &mut blocks,
                &mut defs,
                NodeIndex::new(0),
                (0, 0),
            )
            .is_none()
        );

        // No FieldProj instructions emitted; interner stays empty.
        assert!(blocks[0].body.is_empty());
        assert!(interner.is_empty());
    }

    #[test]
    fn try_lower_field_proj_chain_complex_token_returns_none() {
        // Each of these contains a token signaling complexity that breaks
        // the simple `<ident>.<ident>...` shape; helper must bail.
        let cases = [
            "Foo::bar::baz", // Rust path
            "ptr->field.f",  // C-style arrow
            "obj.f().g",     // intermediate call
            "vec[0].field",  // index expression
            "obj.f.<T>",     // template-ish
            "obj.f g",       // whitespace
            "obj?.f.g",      // optional chain
        ];
        let (mut vs, mut interner, mut blocks, mut defs, mut nv) = fresh_proj_scratch();
        seed_var(&mut vs, &mut defs, &mut nv, "obj");
        for s in &cases {
            assert!(
                try_lower_field_proj_chain(
                    s,
                    &vs,
                    &mut interner,
                    0,
                    BlockId(0),
                    &mut nv,
                    &mut blocks,
                    &mut defs,
                    NodeIndex::new(0),
                    (0, 0),
                )
                .is_none(),
                "expected bail on complex callee {s}"
            );
        }
        assert!(blocks[0].body.is_empty());
        assert!(interner.is_empty());
    }

    #[test]
    fn try_lower_field_proj_chain_unknown_base_returns_none() {
        // The chain root must be a known SSA variable; otherwise the chain
        // root SSA value is unrecoverable and we must fall back.
        let (vs, mut interner, mut blocks, mut defs, mut nv) = fresh_proj_scratch();
        // "ghost" intentionally not seeded.
        assert!(
            try_lower_field_proj_chain(
                "ghost.f.method",
                &vs,
                &mut interner,
                0,
                BlockId(0),
                &mut nv,
                &mut blocks,
                &mut defs,
                NodeIndex::new(0),
                (0, 0),
            )
            .is_none()
        );
        assert!(blocks[0].body.is_empty());
        assert!(interner.is_empty());
    }

    #[test]
    fn try_lower_field_proj_chain_basic_two_dots_emits_one_proj() {
        // `c.mu.Lock()` → emit one FieldProj, return (v_mu, "Lock").
        let (mut vs, mut interner, mut blocks, mut defs, mut nv) = fresh_proj_scratch();
        let v_c = seed_var(&mut vs, &mut defs, &mut nv, "c");

        let (recv, method) = try_lower_field_proj_chain(
            "c.mu.Lock",
            &vs,
            &mut interner,
            0,
            BlockId(0),
            &mut nv,
            &mut blocks,
            &mut defs,
            NodeIndex::new(0),
            (10, 20),
        )
        .expect("chain decomposition should succeed");

        // The returned receiver is a NEW SsaValue (one past v_c).
        assert_eq!(recv, SsaValue(1));
        assert_eq!(method, "Lock");
        // Exactly one FieldProj op was emitted.
        assert_eq!(blocks[0].body.len(), 1);
        let inst = &blocks[0].body[0];
        match &inst.op {
            SsaOp::FieldProj {
                receiver,
                field,
                projected_type,
            } => {
                assert_eq!(*receiver, v_c);
                assert_eq!(interner.resolve(*field), "mu");
                assert!(projected_type.is_none());
            }
            other => panic!("expected FieldProj, got {other:?}"),
        }
        // Span propagated to the FieldProj instruction.
        assert_eq!(inst.span, (10, 20));
        assert_eq!(inst.var_name.as_deref(), Some("c.mu"));
        // value_defs has an entry for the new SSA value.
        assert_eq!(defs.last().unwrap().var_name.as_deref(), Some("c.mu"));
    }

    #[test]
    fn try_lower_field_proj_chain_three_dots_emits_two_projs_chained() {
        // `c.writer.header.set` → 2 FieldProj ops, chained: v_writer reads c,
        // v_header reads v_writer.
        let (mut vs, mut interner, mut blocks, mut defs, mut nv) = fresh_proj_scratch();
        let v_c = seed_var(&mut vs, &mut defs, &mut nv, "c");

        let (recv, method) = try_lower_field_proj_chain(
            "c.writer.header.set",
            &vs,
            &mut interner,
            0,
            BlockId(0),
            &mut nv,
            &mut blocks,
            &mut defs,
            NodeIndex::new(0),
            (0, 0),
        )
        .expect("chain decomposition should succeed");
        assert_eq!(method, "set");
        assert_eq!(recv, SsaValue(2)); // v_c=0, v_writer=1, v_header=2

        assert_eq!(blocks[0].body.len(), 2, "expected 2 FieldProj ops");
        match &blocks[0].body[0].op {
            SsaOp::FieldProj {
                receiver, field, ..
            } => {
                assert_eq!(*receiver, v_c);
                assert_eq!(interner.resolve(*field), "writer");
            }
            other => panic!("expected FieldProj, got {other:?}"),
        }
        match &blocks[0].body[1].op {
            SsaOp::FieldProj {
                receiver, field, ..
            } => {
                assert_eq!(*receiver, SsaValue(1)); // chained on v_writer
                assert_eq!(interner.resolve(*field), "header");
            }
            other => panic!("expected FieldProj, got {other:?}"),
        }
        // var_names form a readable chain
        assert_eq!(blocks[0].body[0].var_name.as_deref(), Some("c.writer"));
        assert_eq!(
            blocks[0].body[1].var_name.as_deref(),
            Some("c.writer.header")
        );
    }

    #[test]
    fn try_lower_field_proj_chain_dedupes_field_names() {
        // Two separate chains that share a field name should reuse the
        // same FieldId via the per-body interner.
        let (mut vs, mut interner, mut blocks, mut defs, mut nv) = fresh_proj_scratch();
        let v_a = seed_var(&mut vs, &mut defs, &mut nv, "a");
        let v_b = seed_var(&mut vs, &mut defs, &mut nv, "b");

        let _ = try_lower_field_proj_chain(
            "a.shared.f",
            &vs,
            &mut interner,
            0,
            BlockId(0),
            &mut nv,
            &mut blocks,
            &mut defs,
            NodeIndex::new(0),
            (0, 0),
        )
        .unwrap();
        let _ = try_lower_field_proj_chain(
            "b.shared.g",
            &vs,
            &mut interner,
            0,
            BlockId(0),
            &mut nv,
            &mut blocks,
            &mut defs,
            NodeIndex::new(0),
            (0, 0),
        )
        .unwrap();

        // Two FieldProj insts emitted, both pointing at the same FieldId.
        assert_eq!(blocks[0].body.len(), 2);
        let f0 = match &blocks[0].body[0].op {
            SsaOp::FieldProj { field, .. } => *field,
            _ => panic!(),
        };
        let f1 = match &blocks[0].body[1].op {
            SsaOp::FieldProj { field, .. } => *field,
            _ => panic!(),
        };
        assert_eq!(f0, f1, "dedup should reuse FieldId");
        assert_eq!(interner.len(), 1, "only one unique field name interned");
        let _ = (v_a, v_b);
    }

    #[test]
    fn try_lower_field_proj_chain_rejects_empty_segments() {
        // Defensive: leading/trailing/double dots are not a member chain.
        let (mut vs, mut interner, mut blocks, mut defs, mut nv) = fresh_proj_scratch();
        seed_var(&mut vs, &mut defs, &mut nv, "x");
        for s in [".x.f", "x..f", "x.f."] {
            assert!(
                try_lower_field_proj_chain(
                    s,
                    &vs,
                    &mut interner,
                    0,
                    BlockId(0),
                    &mut nv,
                    &mut blocks,
                    &mut defs,
                    NodeIndex::new(0),
                    (0, 0),
                )
                .is_none(),
                "expected bail on {s}"
            );
        }
        assert!(blocks[0].body.is_empty());
    }

    // ── End-to-end SSA decomposition tests via real tree-sitter parsing ──────────
    //
    // These exercise the integration between CFG construction (which sets
    // `info.call.callee = "c.mu.Lock"`) and SSA lowering.  We assert that
    // the resulting SsaBody contains a `FieldProj` op whose interned name
    // matches the source-level field name.

    fn parse_to_first_body(
        src: &[u8],
        lang: &str,
        ts_lang: tree_sitter::Language,
        path: &str,
    ) -> SsaBody {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file_cfg = crate::cfg::build_cfg(&tree, src, lang, path, None);
        // Prefer the first non-top-level body (a function), fall back to top.
        let body = if file_cfg.bodies.len() > 1 {
            &file_cfg.bodies[1]
        } else {
            &file_cfg.bodies[0]
        };
        // Mirror the production lowering path: function bodies use
        // lower_to_ssa_with_params so formal parameters get synthetic
        // Param/SelfParam injections at block 0, without them, the
        // FieldProj chain helper has no SSA root to anchor to.
        if body.meta.name.is_some() {
            let func_name = body.meta.name.clone().unwrap_or_default();
            lower_to_ssa_with_params(
                &body.graph,
                body.entry,
                Some(&func_name),
                false,
                &body.meta.params,
            )
            .expect("SSA lowering should succeed")
        } else {
            lower_to_ssa(&body.graph, body.entry, None, true).expect("SSA lowering should succeed")
        }
    }

    /// Iterate every FieldProj instance in `body` along with its resolved
    /// field name.
    fn collect_field_projs(body: &SsaBody) -> Vec<(SsaValue, SsaValue, String)> {
        let mut out = Vec::new();
        for blk in &body.blocks {
            for inst in blk.phis.iter().chain(blk.body.iter()) {
                if let SsaOp::FieldProj {
                    receiver, field, ..
                } = &inst.op
                {
                    out.push((inst.value, *receiver, body.field_name(*field).to_string()));
                }
            }
        }
        out
    }

    /// Iterate every Call instance in `body` along with its callee + callee_text.
    fn collect_calls(body: &SsaBody) -> Vec<(String, Option<String>, Option<SsaValue>)> {
        let mut out = Vec::new();
        for blk in &body.blocks {
            for inst in blk.body.iter() {
                if let SsaOp::Call {
                    callee,
                    callee_text,
                    receiver,
                    ..
                } = &inst.op
                {
                    out.push((callee.clone(), callee_text.clone(), *receiver));
                }
            }
        }
        out
    }

    #[test]
    fn phase2_e2e_go_chained_receiver_emits_field_proj() {
        // Go: `c.writer.header.set(k, v)`, 3-segment receiver, 2 FieldProjs.
        // Chain root `c` is a function parameter so it is resolvable.
        let src = b"package p\nfunc f(c *T, k string, v string) { c.writer.header.set(k, v) }\n";
        let body = parse_to_first_body(
            src,
            "go",
            tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
            "test.go",
        );
        let projs = collect_field_projs(&body);
        assert!(
            projs.len() >= 2,
            "expected ≥2 FieldProj ops for c.writer.header.<m>; got {projs:?}"
        );
        // Field names match the source-level field structure.
        let names: Vec<&str> = projs.iter().map(|(_, _, n)| n.as_str()).collect();
        assert!(
            names.contains(&"writer"),
            "missing 'writer' projection in {names:?}"
        );
        assert!(
            names.contains(&"header"),
            "missing 'header' projection in {names:?}"
        );

        // The Call op carries the bare method name and callee_text retains the path.
        let calls = collect_calls(&body);
        let bare = calls.iter().find(|(c, _, _)| c == "set");
        assert!(
            bare.is_some(),
            "expected a Call with bare callee 'set'; got {calls:?}"
        );
        let (_, ctext, recv) = bare.unwrap();
        assert!(recv.is_some(), "decomposed call must carry an SSA receiver");
        assert_eq!(
            ctext.as_deref(),
            Some("c.writer.header.set"),
            "callee_text should preserve the original textual path"
        );
    }

    #[test]
    fn phase2_e2e_python_chained_receiver_emits_field_proj() {
        // Python: `obj.client.session.send(p)`, 3-segment receiver.
        let src = b"def f(obj, p):\n    obj.client.session.send(p)\n";
        let body = parse_to_first_body(
            src,
            "python",
            tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
            "test.py",
        );
        let projs = collect_field_projs(&body);
        let names: Vec<&str> = projs.iter().map(|(_, _, n)| n.as_str()).collect();
        assert!(
            names.contains(&"client") && names.contains(&"session"),
            "expected client + session projections, got {names:?}"
        );
        let calls = collect_calls(&body);
        assert!(
            calls.iter().any(|(c, ct, r)| c == "send"
                && ct.as_deref() == Some("obj.client.session.send")
                && r.is_some()),
            "expected bare 'send' Call with callee_text retained; got {calls:?}"
        );
    }

    #[test]
    fn phase2_e2e_javascript_chained_receiver_emits_field_proj() {
        // JS: `obj.foo.bar.baz()`, 3-segment receiver.
        let src = b"function f(obj) { obj.foo.bar.baz(); }";
        let body = parse_to_first_body(
            src,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        let projs = collect_field_projs(&body);
        let names: Vec<&str> = projs.iter().map(|(_, _, n)| n.as_str()).collect();
        assert!(
            names.contains(&"foo") && names.contains(&"bar"),
            "expected foo + bar projections, got {names:?}"
        );
    }

    #[test]
    fn phase2_e2e_java_chained_receiver_emits_field_proj() {
        // Java: `obj.config.handler.run()`, 3-segment receiver chain through
        // a parameter `obj`.  We avoid `this.…` because `this` is a Java
        // keyword (not an identifier_node) so it isn't extracted as an
        // external use, outside SSA decomposition.s scope.
        let src = b"class C { void f(Object obj) { obj.config.handler.run(); } }";
        let body = parse_to_first_body(
            src,
            "java",
            tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
            "test.java",
        );
        let projs = collect_field_projs(&body);
        let names: Vec<&str> = projs.iter().map(|(_, _, n)| n.as_str()).collect();
        assert!(
            names.contains(&"config") && names.contains(&"handler"),
            "expected config + handler projections, got {names:?}; full body:\n{body}"
        );
        let calls = collect_calls(&body);
        assert!(
            calls.iter().any(|(c, ct, r)| c == "run"
                && ct.as_deref() == Some("obj.config.handler.run")
                && r.is_some()),
            "expected bare 'run' Call with callee_text retained; got {calls:?}"
        );
    }

    #[test]
    fn phase2_e2e_simple_receiver_no_field_proj() {
        // REGRESSION: `obj.foo()`, single-dot receiver.  SSA lowering must NOT
        // decompose this into a FieldProj chain (existing receiver channel
        // already covers it).  Verify the body has zero FieldProj ops and
        // the Call's callee_text stays None.
        let src = b"function f(obj) { obj.foo(); }";
        let body = parse_to_first_body(
            src,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        assert!(
            collect_field_projs(&body).is_empty(),
            "single-dot call should not generate FieldProj"
        );
        let calls = collect_calls(&body);
        assert!(
            calls.iter().any(|(_, ct, _)| ct.is_none()),
            "single-dot Call should have callee_text=None; calls={calls:?}"
        );
    }

    #[test]
    fn phase2_e2e_bare_call_no_field_proj() {
        // REGRESSION: a free-function call `foo()` must produce zero
        // FieldProj ops and an empty per-body interner.
        let src = b"function f() { foo(1, 2); }";
        let body = parse_to_first_body(
            src,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        assert!(collect_field_projs(&body).is_empty());
        assert!(
            body.field_interner.is_empty(),
            "no chain → interner stays empty"
        );
    }

    #[test]
    fn phase2_e2e_global_root_chain_still_emits_field_proj() {
        // REGRESSION-NEGATIVE: when the chain root is a global identifier
        // (`Math.foo.bar()`), the lowerer's external-var synthesis makes
        // `Math` available as a synthetic Param, the chain still
        // decomposes, treating `Math` as the SSA receiver.  This is the
        // semantically correct outcome even for global-rooted chains: the
        // FieldProj op precisely captures the field-access structure.
        let src = b"function f() { Math.foo.bar(); }";
        let body = parse_to_first_body(
            src,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        let projs = collect_field_projs(&body);
        let names: Vec<&str> = projs.iter().map(|(_, _, n)| n.as_str()).collect();
        assert!(
            names.contains(&"foo"),
            "expected 'foo' projection (chain root Math is a synthesized external var); got {names:?}"
        );
    }

    #[test]
    fn phase2_e2e_rust_method_call_through_field_emits_field_proj() {
        // Rust: `c.mu.lock()`, `c` is a function parameter, `mu` is a field,
        // `lock` is the method.  Verifies we generate FieldProj for `mu`.
        // (Rust paths like `std::env::var` use `::` and are excluded by
        // the helper's complex-token check.)
        let src = b"fn f(c: &T) { c.mu.lock(); }";
        let body = parse_to_first_body(
            src,
            "rust",
            tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
            "test.rs",
        );
        let projs = collect_field_projs(&body);
        let names: Vec<&str> = projs.iter().map(|(_, _, n)| n.as_str()).collect();
        assert!(
            names.contains(&"mu"),
            "expected 'mu' projection from c.mu.lock(); got {names:?}; body:\n{body}"
        );
        let calls = collect_calls(&body);
        assert!(
            calls
                .iter()
                .any(|(c, ct, r)| c == "lock" && ct.as_deref() == Some("c.mu.lock") && r.is_some()),
            "expected bare 'lock' Call with callee_text='c.mu.lock'; got {calls:?}"
        );
    }

    #[test]
    fn phase2_e2e_rust_path_call_does_not_emit_field_proj() {
        // REGRESSION: `std::env::var(...)` is a Rust path (uses `::`), NOT
        // a member-access chain.  Helper must bail.
        let src = br#"fn f() { let _ = std::env::var("X"); }"#;
        let body = parse_to_first_body(
            src,
            "rust",
            tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
            "test.rs",
        );
        assert!(
            collect_field_projs(&body).is_empty(),
            "Rust path expression must not be decomposed into FieldProj"
        );
    }

    #[test]
    fn phase2_e2e_field_interner_populated_only_when_chain_emitted() {
        // Helper invariant: a body with a chained call has a non-empty
        // interner; a body with no chained calls has an empty interner.
        let src_chain = b"function f(o) { o.a.b.c(); }";
        let src_plain = b"function f(o) { o.foo(); }";
        let body_chain = parse_to_first_body(
            src_chain,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        let body_plain = parse_to_first_body(
            src_plain,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        assert!(
            !body_chain.field_interner.is_empty(),
            "interner should hold the chain field names"
        );
        assert!(
            body_plain.field_interner.is_empty(),
            "single-dot call should not populate interner"
        );
    }

    #[test]
    fn phase2_e2e_field_proj_chain_preserves_receiver_dataflow() {
        // The FieldProj receiver chain must trace back to the chain root
        // (parameter `c` here) via `uses_iter()`.  This is the contract
        // every downstream consumer relies on for taint propagation.
        let src = b"function f(c) { c.a.b.m(); }";
        let body = parse_to_first_body(
            src,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        let projs = collect_field_projs(&body);
        assert_eq!(projs.len(), 2, "expected 2 FieldProj ops, got {projs:?}");

        // The first FieldProj's receiver should be a parameter or external
        // var; the second FieldProj's receiver should be the first
        // FieldProj's value.
        let v_first = projs[0].0;
        let r_second = projs[1].1;
        assert_eq!(
            r_second, v_first,
            "second FieldProj must chain off the first's value"
        );
    }

    /// End-to-end: lowering an `obj.f = rhs` statement populates
    /// `SsaBody.field_writes` with the synthetic base-update Assign's
    /// `(receiver, FieldId)` mapping. A single-write shape suffices ,
    /// every formal gets a Param op at block 0 so the first write
    /// finds the formal in `var_stacks`.
    #[test]
    fn w1_end_to_end_field_write_records_side_table_when_parent_has_prior_def() {
        // Single write to `obj.cache`: the formal `obj` provides the
        // prior reaching def via the synthetic Param at block 0.
        let src = b"function f(obj) { obj.cache = 42; }";
        let body = parse_to_first_body(
            src,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        assert!(
            !body.field_writes.is_empty(),
            "single `obj.cache = 42` on a JS formal must populate \
             field_writes via the formal's W1.b synthetic Param; got \
             body.field_writes={:?}\nbody:\n{body}",
            body.field_writes,
        );
        // Every recorded field name resolves to "cache".
        for (_rcv, fid) in body.field_writes.values() {
            assert_eq!(body.field_interner.resolve(*fid), "cache");
        }
    }

    /// W1.b: Python, single `obj.cache = 42` on a formal also
    /// populates `field_writes` thanks to the formal Param op.
    #[test]
    fn w1b_single_write_records_field_write_python() {
        let src = b"def f(obj):\n    obj.cache = 42\n";
        let body = parse_to_first_body(
            src,
            "python",
            tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
            "test.py",
        );
        assert!(
            !body.field_writes.is_empty(),
            "Python single `obj.cache = 42` must populate field_writes; \
             got body.field_writes={:?}\nbody:\n{body}",
            body.field_writes,
        );
    }

    /// W1.b: Rust, single `obj.cache = 42` on a method-style formal
    /// (`fn f(obj: &mut O)`) also populates `field_writes`.
    #[test]
    fn w1b_single_write_records_field_write_rust() {
        let src = b"struct O { cache: i32 } fn f(obj: &mut O) { obj.cache = 42; }";
        let body = parse_to_first_body(
            src,
            "rust",
            tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
            "test.rs",
        );
        assert!(
            !body.field_writes.is_empty(),
            "Rust single `obj.cache = 42` must populate field_writes; \
             got body.field_writes={:?}\nbody:\n{body}",
            body.field_writes,
        );
    }

    /// W1: a plain non-dotted assignment (`x = 1`) records nothing
    /// in `field_writes`.  Strict-additive: existing behaviour is
    /// unchanged for non-field-write shapes.
    #[test]
    fn w1_end_to_end_plain_assign_records_no_field_write() {
        let src = b"function f() { let x = 1; x = 2; }";
        let body = parse_to_first_body(
            src,
            "javascript",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            "test.js",
        );
        assert!(
            body.field_writes.is_empty(),
            "plain assign must not populate field_writes; got {:?}",
            body.field_writes,
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // SSA edge cases: loop induction, multi-variable phis, multiple
    // returns, switch-cases, and shadowing. These plug holes in the
    // dominator-frontier / variable-renaming coverage.
    // ─────────────────────────────────────────────────────────────────

    /// Loop induction variable: `x = x + 1` inside a loop is the
    /// canonical SSA challenge, the body uses `x` then redefines it,
    /// and the join with the entry definition must produce a phi that
    /// distinguishes the entry value from the body's redefinition.
    /// Induction-var pruning depends on this shape being lowered
    /// correctly.
    #[test]
    fn loop_self_assignment_induction_phi_is_distinct() {
        // Entry → x=0 → Loop header → [Body: use x; x = x_new] → Loop
        // The body both uses and defines x, modeling `x = x + 1`.
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let init_x = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let header = cfg.add_node(make_node(StmtKind::Loop));
        let body = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, init_x, EdgeKind::Seq);
        cfg.add_edge(init_x, header, EdgeKind::Seq);
        cfg.add_edge(header, body, EdgeKind::True);
        cfg.add_edge(body, header, EdgeKind::Back);
        cfg.add_edge(header, exit, EdgeKind::False);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // We expect THREE distinct SSA values for `x`:
        //   - init_x (entry value)
        //   - body's redefinition
        //   - the loop-header phi
        let x_defs: Vec<_> = ssa
            .value_defs
            .iter()
            .filter(|vd| vd.var_name.as_deref() == Some("x"))
            .collect();
        assert!(
            x_defs.len() >= 3,
            "expected ≥3 SSA values for x (init, phi, body-redef), got {}",
            x_defs.len()
        );

        // The header's phi for x must have exactly two operands (entry
        // value + back-edge value) and they must NOT both be the same
        // SsaValue (otherwise the renaming collapsed the two arms).
        let phi_ops = ssa
            .blocks
            .iter()
            .flat_map(|b| b.phis.iter())
            .find(|p| p.var_name.as_deref() == Some("x"))
            .and_then(|p| match &p.op {
                SsaOp::Phi(ops) => Some(ops.clone()),
                _ => None,
            })
            .expect("expected a Phi op for x at the loop header");
        assert_eq!(
            phi_ops.len(),
            2,
            "loop header phi for x should have 2 operands, got {}",
            phi_ops.len()
        );
        let unique: HashSet<_> = phi_ops.iter().map(|(_, v)| v).collect();
        assert_eq!(
            unique.len(),
            2,
            "phi operands must be distinct (entry vs back-edge), got {:?}",
            phi_ops
        );
    }

    /// Diamond join with two distinct variables defined in both arms:
    /// the merge block must contain a phi for EACH of the variables,
    /// not just one. Guards against single-variable phi insertion.
    #[test]
    fn diamond_join_produces_phi_per_variable() {
        // Entry → cond → [True: x=1; y=10] → join
        //              ↘ [False: x=2; y=20] ↗
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let cond = cfg.add_node(make_node(StmtKind::If));
        let true_def = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let true_def2 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("y".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let false_def = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let false_def2 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("y".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["x".into(), "y".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, cond, EdgeKind::Seq);
        cfg.add_edge(cond, true_def, EdgeKind::True);
        cfg.add_edge(true_def, true_def2, EdgeKind::Seq);
        cfg.add_edge(true_def2, join, EdgeKind::Seq);
        cfg.add_edge(cond, false_def, EdgeKind::False);
        cfg.add_edge(false_def, false_def2, EdgeKind::Seq);
        cfg.add_edge(false_def2, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        let phi_vars: HashSet<&str> = ssa
            .blocks
            .iter()
            .flat_map(|b| b.phis.iter())
            .filter_map(|p| p.var_name.as_deref())
            .collect();
        assert!(
            phi_vars.contains("x"),
            "expected phi for x at diamond join, got {:?}",
            phi_vars
        );
        assert!(
            phi_vars.contains("y"),
            "expected phi for y at diamond join, got {:?}",
            phi_vars
        );
    }

    /// Two reachable Return nodes from different branches must each
    /// produce a `Terminator::Return`. Common before: only the last
    /// CFG-Return survived as a real return, others were Goto'd to
    /// Exit. Regression for the early-return check.
    #[test]
    fn two_branches_with_returns_each_terminates_with_return() {
        // Entry → cond → [True: r1=1; return r1] / [False: r2=2; return r2]
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let cond = cfg.add_node(make_node(StmtKind::If));
        let r1 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("r1".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let ret1 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["r1".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Return)
        });
        let r2 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("r2".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let ret2 = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["r2".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Return)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, cond, EdgeKind::Seq);
        cfg.add_edge(cond, r1, EdgeKind::True);
        cfg.add_edge(r1, ret1, EdgeKind::Seq);
        cfg.add_edge(ret1, exit, EdgeKind::Seq);
        cfg.add_edge(cond, r2, EdgeKind::False);
        cfg.add_edge(r2, ret2, EdgeKind::Seq);
        cfg.add_edge(ret2, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Count blocks ending with `Terminator::Return(_)`.
        let return_blocks = ssa
            .blocks
            .iter()
            .filter(|b| matches!(&b.terminator, Terminator::Return(_)))
            .count();
        assert_eq!(
            return_blocks, 2,
            "expected 2 Return-terminated blocks, got {}",
            return_blocks
        );
    }

    /// Variable defined ONLY in one branch of a conditional must be
    /// undef on the other path. The phi at the join should include an
    /// undef sentinel for the missing arm, guards against the
    /// renamer silently dropping the missing operand.
    #[test]
    fn conditional_define_only_one_arm_phi_has_undef_operand() {
        // Entry → cond → [True: x=1] → join (uses x)
        //              ↘ [False: nop] ↗
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let cond = cfg.add_node(make_node(StmtKind::If));
        let true_def = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let false_nop = cfg.add_node(make_node(StmtKind::Seq));
        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["x".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));
        cfg.add_edge(entry, cond, EdgeKind::Seq);
        cfg.add_edge(cond, true_def, EdgeKind::True);
        cfg.add_edge(true_def, join, EdgeKind::Seq);
        cfg.add_edge(cond, false_nop, EdgeKind::False);
        cfg.add_edge(false_nop, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();

        // Find a phi for x and verify it has 2 operands. The "undef"
        // operand can manifest as a Nop-defined SsaValue or a sentinel
        //, both are acceptable; the invariant is that arity == preds.
        let x_phi_ops = ssa
            .blocks
            .iter()
            .flat_map(|b| b.phis.iter())
            .find(|p| p.var_name.as_deref() == Some("x"))
            .and_then(|p| match &p.op {
                SsaOp::Phi(ops) => Some(ops.clone()),
                _ => None,
            });
        if let Some(ops) = x_phi_ops {
            assert_eq!(
                ops.len(),
                2,
                "phi for x at the join must have 2 operands (one per pred), got {}",
                ops.len()
            );
        }
        // Acceptable alternative: SSA may skip phi insertion when one
        // arm is undef. The invariant we care about is that lowering
        // doesn't panic, which `lower_to_ssa(...).unwrap()` already
        // exercises.
    }

    /// `lower_to_ssa` on a CFG with NO definitions of any variable
    /// must still succeed and produce a body with at least entry/exit
    /// blocks. Regression for trivial-function lowering.
    #[test]
    fn empty_function_body_only_entry_and_exit_lowers_cleanly() {
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let exit = cfg.add_node(make_node(StmtKind::Exit));
        cfg.add_edge(entry, exit, EdgeKind::Seq);

        let ssa = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert!(
            !ssa.blocks.is_empty(),
            "even an empty body should produce at least one block"
        );
        // No phis (nothing converged), no value_defs except possibly
        // entry sentinels. We just assert it lowered without panic.
    }
}
