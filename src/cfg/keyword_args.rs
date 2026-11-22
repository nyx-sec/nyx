//! Keyword-argument placement for Ruby calls into same-file methods.
//!
//! A Ruby keyword argument (`run(name, dir: x)`) is a `pair` in the call's
//! argument list, so it takes the next positional slot there, while the callee
//! binds it by name (`def run(name, dir: '.')`).  Callers and callees agree on
//! slots only by coincidence, so the interprocedural step would feed `x` to the
//! wrong parameter when keywords are reordered, omitted, or mixed with
//! optional parameters.
//!
//! This pass runs once the file's methods are known.  For a call that names a
//! same-file method, it moves each keyword argument to the slot of the
//! parameter of that name and leaves holes empty, so that argument position `i`
//! always means parameter `i` for the rest of the pipeline.  Calls that touch
//! a label (source, sanitizer or sink) are skipped: their positions are the
//! label table's syntactic ones, not a user-defined signature.  Cross-file
//! callees keep the syntactic order.

use super::{BodyCfg, FuncSummaries, NodeInfo, StmtKind};

pub(super) fn reorder_keyword_args(bodies: &mut [BodyCfg], summaries: &FuncSummaries) {
    for body in bodies.iter_mut() {
        let indices: Vec<_> = body.graph.node_indices().collect();
        for idx in indices {
            let info = &body.graph[idx];
            if info.call.kw_arg_positions.is_empty() || !is_plain_call(info) {
                continue;
            }
            let Some(callee) = info.call.callee.as_deref() else {
                continue;
            };
            let Some(params) = callee_params(callee, summaries) else {
                continue;
            };
            if let Some(map) = slot_map(info, params) {
                apply(&mut body.graph[idx], &map);
            }
        }
    }
}

fn is_plain_call(info: &NodeInfo) -> bool {
    info.kind == StmtKind::Call
        && info.taint.labels.is_empty()
        && info.call.nested_calls.is_none()
        && info.call.sink_payload_args.is_none()
        && info.call.gate_filters.is_empty()
        && !info.call.is_constructor
}

/// Parameter names of the same-file method a call refers to.  `None` when no
/// method of that name exists or same-named methods disagree on their
/// parameters, since the receiver type is unknown.
fn callee_params<'a>(callee: &str, summaries: &'a FuncSummaries) -> Option<&'a [String]> {
    let bare = callee.rsplit(['.', ':']).next().unwrap_or(callee);
    let mut found: Option<&[String]> = None;
    for (key, sum) in summaries {
        if key.name != bare {
            continue;
        }
        match found {
            None => found = Some(&sum.param_names),
            Some(prev) if prev == sum.param_names.as_slice() => {}
            Some(_) => return None,
        }
    }
    found.filter(|p| !p.is_empty())
}

/// `(old_position, new_position)` for every keyword argument, or `None` when
/// the call cannot be placed unambiguously.
fn slot_map(info: &NodeInfo, params: &[String]) -> Option<Vec<(usize, usize)>> {
    let positional = info
        .call
        .kw_arg_positions
        .iter()
        .map(|(_, p)| *p)
        .min()
        .unwrap_or(0);
    let mut used = vec![false; params.len()];
    let mut map = Vec::with_capacity(info.call.kw_arg_positions.len());
    for (name, old) in &info.call.kw_arg_positions {
        let new = params.iter().position(|p| p == name)?;
        if new < positional || used[new] || *old >= info.call.arg_uses.len() {
            return None;
        }
        used[new] = true;
        map.push((*old, new));
    }
    Some(map)
}

fn place<T: Clone + Default>(
    v: &mut Vec<T>,
    old_len: usize,
    new_len: usize,
    map: &[(usize, usize)],
) {
    if v.len() != old_len {
        return;
    }
    let mut out = v.clone();
    out.resize(new_len, T::default());
    for (old, new) in map {
        out[*new] = v[*old].clone();
        if new != old && !map.iter().any(|(_, n)| n == old) {
            out[*old] = T::default();
        }
    }
    *v = out;
}

fn apply(info: &mut NodeInfo, map: &[(usize, usize)]) {
    let old_len = info.call.arg_uses.len();
    let new_len = map
        .iter()
        .map(|(_, n)| n + 1)
        .max()
        .unwrap_or(0)
        .max(old_len);
    place(&mut info.call.arg_uses, old_len, new_len, map);
    place(&mut info.call.arg_string_literals, old_len, new_len, map);
    place(&mut info.call.arg_string_prefixes, old_len, new_len, map);
    place(&mut info.arg_callees, old_len, new_len, map);
    let mut bits = info.call.arg_bare_names;
    for (old, _) in map {
        if *old < 64 {
            bits &= !(1u64 << old);
        }
    }
    for (old, new) in map {
        if *old < 64 && *new < 64 && info.call.arg_bare_names & (1u64 << old) != 0 {
            bits |= 1u64 << new;
        }
    }
    info.call.arg_bare_names = bits;
    info.call.kw_arg_positions = info
        .call
        .kw_arg_positions
        .iter()
        .zip(map)
        .map(|((name, _), (_, new))| (name.clone(), *new))
        .collect();
}
