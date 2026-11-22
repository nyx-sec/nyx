//! Module-level string constants as URL prefixes.
//!
//! `const API = "https://api.example.com/"; axios.get(API + id)` builds a URL
//! whose host is fixed, but the prefix extractor only reads literals written
//! at the use site.  The extractor records a leading identifier on the node
//! (`NodeInfo::string_prefix_ident`); once every body of the file is built,
//! this pass resolves those identifiers against the file's module constants
//! and turns them into ordinary `string_prefix` values.
//!
//! A constant qualifies only when the name has exactly one definition in the
//! whole file, at module level, with a quoted string literal as its value.  Any
//! other definition counts against it, in any body, because a function can
//! rebind a module variable (`global API`, an undeclared JS assignment) and
//! every other function sees the new value.  A parameter is the exception: it
//! only shadows the name inside its own function and the functions nested in
//! it, so a use there is left alone while the rest of the file still resolves.

use super::{BodyCfg, BodyId};
use std::collections::{BTreeMap, HashMap, HashSet};

/// The quoted string literal in `text` without its quotes, or `None` when it
/// is not a single plain string: no quotes, mismatched quotes, a template
/// literal with a `${}` substitution, a `#{}` interpolation, or the quote
/// character inside (an escaped quote, or text such as `"a" + "b"` and
/// Python's implicit `"a" "b"` that only starts and ends with a quote).
fn string_literal_value(text: &str) -> Option<&str> {
    let t = text.trim();
    if t.len() < 2 {
        return None;
    }
    let (first, last) = (t.as_bytes()[0], t.as_bytes()[t.len() - 1]);
    if first != last || !matches!(first, b'"' | b'\'' | b'`') {
        return None;
    }
    let inner = &t[1..t.len() - 1];
    if inner.contains("${") || inner.contains("#{") || inner.as_bytes().contains(&first) {
        return None;
    }
    Some(inner)
}

/// Module-level string constants of the file, name to value.
fn collect(bodies: &[BodyCfg]) -> BTreeMap<String, String> {
    let Some(top) = bodies.first() else {
        return BTreeMap::new();
    };
    let mut candidates: BTreeMap<String, String> = BTreeMap::new();
    for idx in top.graph.node_indices() {
        let info = &top.graph[idx];
        let (Some(name), Some(text)) = (
            info.taint.defines.as_deref(),
            info.taint.const_text.as_deref(),
        ) else {
            continue;
        };
        if !info.taint.uses.is_empty() {
            continue;
        }
        if let Some(value) = string_literal_value(text) {
            candidates.insert(name.to_string(), value.to_string());
        }
    }
    if candidates.is_empty() {
        return candidates;
    }
    // Every other definition of the name, in any body, disqualifies it.
    let mut definitions: HashMap<&str, u32> = HashMap::new();
    for body in bodies {
        for idx in body.graph.node_indices() {
            let info = &body.graph[idx];
            for name in info
                .taint
                .defines
                .iter()
                .chain(info.taint.extra_defines.iter())
            {
                *definitions.entry(name.as_str()).or_default() += 1;
            }
        }
    }
    candidates.retain(|name, _| definitions.get(name.as_str()).copied() == Some(1));
    candidates
}

/// Parameter names visible in each body: its own and those of every enclosing
/// function body.  The top-level body has none.
fn params_in_scope(bodies: &[BodyCfg]) -> Vec<HashSet<String>> {
    let index_of: HashMap<BodyId, usize> = bodies
        .iter()
        .enumerate()
        .map(|(i, b)| (b.meta.id, i))
        .collect();
    bodies
        .iter()
        .map(|body| {
            let mut names = HashSet::new();
            let mut cur = Some(body);
            // The parent chain is acyclic; the bound only guards a corrupt one.
            for _ in 0..bodies.len() {
                let Some(b) = cur else { break };
                names.extend(b.meta.params.iter().cloned());
                names.extend(b.meta.param_destructured_fields.iter().flatten().cloned());
                cur = b
                    .meta
                    .parent_body_id
                    .and_then(|p| index_of.get(&p))
                    .map(|&i| &bodies[i]);
            }
            names
        })
        .collect()
}

/// Resolve every recorded leading identifier into a `string_prefix`, then
/// drop the marker.
pub(super) fn resolve_prefix_idents(bodies: &mut [BodyCfg]) {
    let any_pending = bodies.iter().any(|b| {
        b.graph
            .node_weights()
            .any(|n| n.string_prefix_ident.is_some())
    });
    if !any_pending {
        return;
    }
    let consts = collect(bodies);
    let shadowed = params_in_scope(bodies);
    for (body, params) in bodies.iter_mut().zip(&shadowed) {
        for info in body.graph.node_weights_mut() {
            let Some((name, tail)) = info.string_prefix_ident.take() else {
                continue;
            };
            if info.string_prefix.is_none()
                && !params.contains(&name)
                && let Some(value) = consts.get(&name)
            {
                info.string_prefix = Some(format!("{value}{tail}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::string_literal_value;

    #[test]
    fn only_a_single_plain_literal_is_a_value() {
        assert_eq!(
            string_literal_value("'https://api.example.com/'"),
            Some("https://api.example.com/")
        );
        assert_eq!(string_literal_value("`https://h/`"), Some("https://h/"));
        for text in [
            "\"https://a\" \"pi.example.com/\"",
            "\"https://a\" + \"b/\"",
            "`https://${host}/`",
            "\"https://#{host}/\"",
            "\"a\\\"b\"",
            "f\"https://h/\"",
            "API",
            "\"",
        ] {
            assert_eq!(string_literal_value(text), None, "{text}");
        }
    }
}
