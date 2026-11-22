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

/// Calls whose result never ends with a path separator: they strip trailing
/// ones (`path.resolve('/srv/uploads/')` is `/srv/uploads`).  A root built
/// by one of these and then used as a bare `startsWith` / `startswith` /
/// `HasPrefix` prefix also matches a sibling directory sharing the name.
const SEPARATOR_STRIPPING_CALLEES: &[&str] = &[
    "path.resolve",
    "path.posix.resolve",
    "path.win32.resolve",
    "fs.realpathSync",
    "fs.realpath",
    "os.path.abspath",
    "os.path.realpath",
    "os.path.normpath",
    "abspath",
    "realpath",
    "normpath",
    "filepath.Abs",
    "filepath.Clean",
    "filepath.EvalSymlinks",
    "path.Clean",
];

/// How a root constant ends.
enum RootEnd {
    /// Ends with a separator: a prefix test against it is a containment test.
    Terminated,
    /// Provably has no trailing separator.
    Unterminated,
}

/// The right-hand side of the assignment or declaration in `stmt`, without a
/// trailing `;`.  `None` when there is no plain `=` (comparison operators and
/// `=>` do not count).
fn assigned_value(stmt: &str) -> Option<&str> {
    let b = stmt.as_bytes();
    let eq = (0..b.len()).find(|&i| {
        b[i] == b'='
            && b.get(i + 1) != Some(&b'=')
            && b.get(i + 1) != Some(&b'>')
            && !(i > 0 && matches!(b[i - 1], b'=' | b'!' | b'<' | b'>'))
    })?;
    let rhs = stmt[eq + 1..].trim().trim_end_matches(';').trim_end();
    (!rhs.is_empty()).then_some(rhs)
}

/// True when `rhs` is exactly one call `callee(...)` with nothing after the
/// closing parenthesis, so no `+ sep` or other suffix changes its result.
fn is_single_call_to(rhs: &str, callees: &[&str]) -> bool {
    let Some(open) = rhs.find('(') else {
        return false;
    };
    if !callees.contains(&rhs[..open].trim()) {
        return false;
    }
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let bytes = rhs.as_bytes();
    let mut i = open;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 1;
            } else if c == q {
                quote = None;
            }
        } else {
            match c {
                b'"' | b'\'' | b'`' => quote = Some(c),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1 == bytes.len();
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    false
}

/// Classify the value a defining statement assigns, when it is a plain string
/// literal or one separator-stripping path call and nothing else.
fn root_end_of(stmt: &str) -> Option<RootEnd> {
    let rhs = assigned_value(stmt)?;
    if let Some(value) = string_literal_value(rhs) {
        return Some(
            if crate::abstract_interp::path_domain::root_ends_with_separator(value) {
                RootEnd::Terminated
            } else {
                RootEnd::Unterminated
            },
        );
    }
    is_single_call_to(rhs, SEPARATOR_STRIPPING_CALLEES).then_some(RootEnd::Unterminated)
}

/// Flag every prefix-test condition whose root is a bare identifier bound
/// once, to a literal or separator-stripping call, that has no trailing
/// separator.  The name must have exactly one definition in the whole file.  Anything else (a parameter, a
/// rebound name, an opaque expression) is left unflagged and keeps the
/// opaque-root treatment, since the root's bytes are unknown.
pub(super) fn resolve_root_idents(bodies: &mut [BodyCfg], lang: &str, code: &[u8]) {
    // Languages whose prefix test is a plain string test.  Java and Rust
    // `startsWith` / `starts_with` may be component-wise `Path` methods, and
    // PHP / Ruby spell roots with sigils this pass does not read.
    if !matches!(lang, "javascript" | "typescript" | "tsx" | "python" | "go") {
        return;
    }
    let mut pending: Vec<(usize, petgraph::graph::NodeIndex, String)> = Vec::new();
    for (bi, body) in bodies.iter().enumerate() {
        for idx in body.graph.node_indices() {
            let Some(text) = body.graph[idx].condition_text.as_deref() else {
                continue;
            };
            if let Some(root) = crate::abstract_interp::path_domain::starts_with_root_arg(text)
                && is_bare_identifier(root)
            {
                pending.push((bi, idx, root.to_string()));
            }
        }
    }
    if pending.is_empty() {
        return;
    }
    let params = params_in_scope(bodies);
    // Definition counts per name: whole file, and the module-level node.
    let mut file_defs: HashMap<&str, u32> = HashMap::new();
    for body in bodies.iter() {
        for info in body.graph.node_weights() {
            for name in info
                .taint
                .defines
                .iter()
                .chain(info.taint.extra_defines.iter())
            {
                *file_defs.entry(name.as_str()).or_default() += 1;
            }
        }
    }
    let mut flagged: Vec<(usize, petgraph::graph::NodeIndex)> = Vec::new();
    for (bi, idx, name) in &pending {
        if params[*bi].contains(name) || file_defs.get(name.as_str()).copied() != Some(1) {
            continue;
        }
        let def = bodies.iter().find_map(|b| {
            b.graph
                .node_weights()
                .find(|n| n.taint.defines.as_deref() == Some(name.as_str()))
        });
        let stmt = def.and_then(|n| code.get(n.ast.span.0..n.ast.span.1));
        let stmt = stmt.and_then(|b| std::str::from_utf8(b).ok());
        if let Some(RootEnd::Unterminated) = stmt.and_then(root_end_of) {
            flagged.push((*bi, *idx));
        }
    }
    for (bi, idx) in flagged {
        bodies[bi].graph[idx].root_unterminated = true;
    }
}

fn is_bare_identifier(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
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
