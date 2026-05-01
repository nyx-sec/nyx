#![allow(clippy::collapsible_if, clippy::redundant_closure)]

//! Static hash-map lookup abstract analysis.
//!
//! Recognises the idiom
//! ```ignore
//! let mut table = HashMap::new();
//! table.insert(K1, V1);
//! table.insert(K2, V2);
//! let cmd = table.get(k).copied().unwrap_or("safe");
//! ```
//! where every insert's *value* slot is a syntactic string literal and the
//! final lookup is dereffed via a literal fallback (`.unwrap_or(LIT)`).  The
//! result `cmd` is then provably bounded to the finite set
//! `{V1, V2, …, "safe"}`, regardless of what `k` carries, taint-flavour or
//! otherwise.  Downstream sink suppression consumes this finite set to
//! clear SHELL/FILE/SQL injection findings whose payload is proved to be
//! metacharacter-free.
//!
//! ## SSA shape assumption
//!
//! The taint CFG collapses each method chain into **one** SSA `Call`
//! instruction whose `callee` text is the entire chain's "function" expression
//! (e.g. `"table.get(key).copied().unwrap_or"` for `table.get(key).copied()
//! .unwrap_or("safe")`) and whose `receiver` is the root identifier's SSA
//! value.  We therefore do not need to walk SSA `.copied()` / `.unwrap_or`
//! instructions as separate hops, pattern-matching on the callee text is
//! the source of truth.  String-literal arguments that the callee text
//! elides (e.g. the fallback `"safe"`) are read from the CFG node's
//! `arg_string_literals`, populated during CFG construction.
//!
//! Scope is deliberately narrow: only same-function static maps, only
//! literal-valued inserts, no escape beyond recognised mutate/read methods.
//! Any deviation (dynamic insert, callee not in the allow-list, map used as
//! a plain argument, map returned, map joined across a phi) invalidates the
//! candidate.  Missed detection is safe, it just falls through to existing
//! behaviour.

use std::collections::{HashMap, HashSet};

use super::const_prop::ConstLattice;
use super::ir::*;
use crate::cfg::Cfg;
use crate::symbol::Lang;

/// Output of the static-map analysis: SSA values whose concrete string value
/// is provably in a finite set, plus the set itself (sorted + deduped).
#[derive(Clone, Debug, Default)]
pub struct StaticMapResult {
    pub finite_string_values: HashMap<SsaValue, Vec<String>>,
}

impl StaticMapResult {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.finite_string_values.is_empty()
    }
}

/// Rust-specific constructors that produce an empty map value.
fn is_rust_map_constructor(callee: &str) -> bool {
    let leaf_after_colon = callee.rsplit("::").next().unwrap_or(callee);
    if leaf_after_colon != "new" {
        return false;
    }
    let type_part = callee.rsplit("::").nth(1).unwrap_or("");
    matches!(type_part, "HashMap" | "BTreeMap")
}

/// Classification of a Call whose receiver is a candidate map.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MapUse {
    /// `{var}.insert(K, V)`, value contributes to the finite domain.
    Insert,
    /// `{var}.get(K)[.copied()|.cloned()|.as_deref()|.as_ref()]*.unwrap_or`
    ///, lookup result is bounded by the inserted values plus the fallback
    /// literal on the CFG node.
    StaticLookup,
    /// Whitelisted read-only method (no reference leak).
    ReadOnly,
    /// Anything else, invalidates the map candidate.
    Escape,
}

/// Classify the callee of a Call whose `receiver` SSA value points to a
/// candidate map bound to `map_var`.  Returns [`MapUse::Escape`] when the
/// callee doesn't match any recognised pattern so the caller invalidates
/// the map rather than trusting an unknown mutation.
fn classify_map_use(callee: &str, map_var: &str) -> MapUse {
    // Fast-path: exact single-method calls on the receiver.
    let method = callee
        .strip_prefix(map_var)
        .and_then(|rest| rest.strip_prefix('.'));
    if let Some(method) = method {
        // Single identifier method with no trailing chain.
        match method {
            "insert" => return MapUse::Insert,
            "contains_key" | "len" | "is_empty" | "clear" => return MapUse::ReadOnly,
            _ => {}
        }
        // Chained lookup: must start with `get(…)` and end with `.unwrap_or`.
        if let Some(rest) = method.strip_prefix("get(") {
            if let Some(after_args) = scan_past_balanced_parens(rest) {
                if is_identity_chain_ending_in_unwrap_or(after_args) {
                    return MapUse::StaticLookup;
                }
            }
        }
    }
    MapUse::Escape
}

/// Given `s` just after an opening `(`, return the slice after the matching
/// close `)`.  Returns `None` when parens are unbalanced.
fn scan_past_balanced_parens(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut depth: i32 = 1;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[i + 1..]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Return `true` when `s` is a sequence of zero or more identity chain
/// methods (`.copied()`, `.cloned()`, `.as_deref()`, `.as_ref()`) followed
/// by `.unwrap_or` (and nothing else).  The trailing arg list of
/// `.unwrap_or` is elided in the callee text, it appears in the CFG node's
/// `arg_string_literals` instead.
fn is_identity_chain_ending_in_unwrap_or(mut s: &str) -> bool {
    const IDENTS: &[&str] = &[".copied()", ".cloned()", ".as_deref()", ".as_ref()"];
    loop {
        if s == ".unwrap_or" {
            return true;
        }
        let mut advanced = false;
        for id in IDENTS {
            if let Some(rest) = s.strip_prefix(id) {
                s = rest;
                advanced = true;
                break;
            }
        }
        if !advanced {
            return false;
        }
    }
}

fn resolve_alias(v: SsaValue, aliases: &HashMap<SsaValue, SsaValue>) -> SsaValue {
    let mut cur = v;
    for _ in 0..64 {
        match aliases.get(&cur) {
            Some(&next) if next != cur => cur = next,
            _ => break,
        }
    }
    cur
}

/// Run the analysis.  Bails out immediately for non-Rust bodies, the current
/// pattern set only models Rust `std::collections::HashMap`.
pub fn analyze(
    body: &SsaBody,
    cfg: &Cfg,
    lang: Option<Lang>,
    _const_values: &HashMap<SsaValue, ConstLattice>,
) -> StaticMapResult {
    if lang != Some(Lang::Rust) {
        return StaticMapResult::empty();
    }

    // ── 1. Discover candidate map allocations + their bound var name ──────
    // The var_name is the identifier the CFG builder attaches to the define
    // site of the let-binding.  Without a var_name we can't pattern-match
    // receiver uses in callee text, so such allocations are skipped.
    let mut candidates: HashMap<SsaValue, String> = HashMap::new();
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let SsaOp::Call { callee, .. } = &inst.op {
                if is_rust_map_constructor(callee) {
                    if let Some(name) = inst.var_name.as_deref() {
                        if !name.is_empty() {
                            candidates.insert(inst.value, name.to_string());
                        }
                    }
                }
            }
        }
    }
    if candidates.is_empty() {
        return StaticMapResult::empty();
    }

    // ── 2. Build trivial alias chain: single-use Assign `v = w` where w is
    //    a known (or aliased) candidate value.  Keeps us robust to wrapper
    //    copies SSA lowering occasionally introduces.
    let mut aliases: HashMap<SsaValue, SsaValue> = HashMap::new();
    for block in &body.blocks {
        for inst in &block.body {
            if let SsaOp::Assign(uses) = &inst.op {
                if uses.len() == 1 {
                    let src = resolve_alias(uses[0], &aliases);
                    if candidates.contains_key(&src) {
                        aliases.insert(inst.value, src);
                    }
                }
            }
        }
    }
    let canonicalise = |v: SsaValue| -> Option<SsaValue> {
        let c = resolve_alias(v, &aliases);
        if candidates.contains_key(&c) {
            Some(c)
        } else {
            None
        }
    };

    // ── 3. Walk every instruction, classifying references to any candidate.
    //    Collect per-candidate inserted literal values and mark invalidating
    //    escapes (phi operand, non-whitelisted method, plain argument use,
    //    non-copy Assign, Return).
    let mut inserted: HashMap<SsaValue, HashSet<String>> = HashMap::new();
    let mut invalid: HashSet<SsaValue> = HashSet::new();
    // Each lookup site: (map, result SSA value, fallback literal).
    let mut lookups: Vec<(SsaValue, SsaValue, String)> = Vec::new();
    for c in candidates.keys() {
        inserted.insert(*c, HashSet::new());
    }

    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            match &inst.op {
                SsaOp::Phi(operands) => {
                    for (_, v) in operands {
                        if let Some(canon) = canonicalise(*v) {
                            invalid.insert(canon);
                        }
                    }
                }
                SsaOp::Call {
                    callee,
                    args,
                    receiver,
                    ..
                } => {
                    if candidates.contains_key(&inst.value) && is_rust_map_constructor(callee) {
                        continue;
                    }
                    if let Some(map) = receiver.and_then(|r| canonicalise(r)) {
                        let map_var = candidates.get(&map).cloned().unwrap_or_default();
                        match classify_map_use(callee, &map_var) {
                            MapUse::Insert => {
                                let node_info = &cfg[inst.cfg_node];
                                let value_lit =
                                    node_info.call.arg_string_literals.get(1).cloned().flatten();
                                match value_lit {
                                    Some(lit) => {
                                        inserted.entry(map).or_default().insert(lit);
                                    }
                                    None => {
                                        invalid.insert(map);
                                    }
                                }
                            }
                            MapUse::StaticLookup => {
                                let node_info = &cfg[inst.cfg_node];
                                if let Some(Some(fallback)) =
                                    node_info.call.arg_string_literals.first().cloned()
                                {
                                    lookups.push((map, inst.value, fallback));
                                }
                                // A non-literal fallback silently falls
                                // through: the map stays valid, we just
                                // don't emit a finite domain for this site.
                            }
                            MapUse::ReadOnly => {}
                            MapUse::Escape => {
                                invalid.insert(map);
                            }
                        }
                    }
                    for group in args {
                        for &v in group {
                            if let Some(canon) = canonicalise(v) {
                                invalid.insert(canon);
                            }
                        }
                    }
                }
                SsaOp::Assign(uses) if uses.len() != 1 => {
                    for &u in uses {
                        if let Some(canon) = canonicalise(u) {
                            invalid.insert(canon);
                        }
                    }
                }
                _ => {}
            }
        }
        if let Terminator::Return(Some(v)) = &block.terminator {
            if let Some(canon) = canonicalise(*v) {
                invalid.insert(canon);
            }
        }
    }

    // ── 4. Emit results for still-valid candidates with at least one insert.
    let mut result = StaticMapResult::default();
    for (map, lookup_val, fallback) in lookups {
        if invalid.contains(&map) {
            continue;
        }
        let lits = match inserted.get(&map) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let mut domain: Vec<String> = lits.iter().cloned().collect();
        domain.push(fallback);
        domain.sort();
        domain.dedup();
        result.finite_string_values.insert(lookup_val, domain);
    }
    result
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_map_constructor_matches() {
        assert!(is_rust_map_constructor("HashMap::new"));
        assert!(is_rust_map_constructor("std::collections::HashMap::new"));
        assert!(is_rust_map_constructor("BTreeMap::new"));
        assert!(!is_rust_map_constructor("HashMap::from"));
        assert!(!is_rust_map_constructor("HashMap::with_capacity"));
        assert!(!is_rust_map_constructor("Vec::new"));
    }

    #[test]
    fn classify_insert_call() {
        assert_eq!(classify_map_use("table.insert", "table"), MapUse::Insert);
    }

    #[test]
    fn classify_read_only_call() {
        assert_eq!(
            classify_map_use("table.contains_key", "table"),
            MapUse::ReadOnly
        );
        assert_eq!(classify_map_use("table.len", "table"), MapUse::ReadOnly);
        // Iterator-returning methods (values/iter/keys) escape: they leak
        // references that can flow anywhere.
        assert_eq!(classify_map_use("table.values", "table"), MapUse::Escape);
        assert_eq!(classify_map_use("table.iter", "table"), MapUse::Escape);
    }

    #[test]
    fn classify_static_lookup_with_copied() {
        assert_eq!(
            classify_map_use("table.get(key.as_str()).copied().unwrap_or", "table"),
            MapUse::StaticLookup
        );
    }

    #[test]
    fn classify_static_lookup_without_identity_chain() {
        // `.unwrap_or` directly after `.get(...)` also qualifies, Rust
        // `HashMap::get` returns `Option<&V>`, so `.unwrap_or(&"safe")` is
        // syntactically valid and equally bounded.
        assert_eq!(
            classify_map_use("table.get(k).unwrap_or", "table"),
            MapUse::StaticLookup
        );
    }

    #[test]
    fn classify_static_lookup_mixed_identity_chain() {
        assert_eq!(
            classify_map_use("t.get(k).as_deref().cloned().unwrap_or", "t"),
            MapUse::StaticLookup
        );
    }

    #[test]
    fn classify_rejects_unknown_terminator() {
        // `.unwrap_or_else(|| …)` is not modelled, closure can return anything.
        assert_eq!(
            classify_map_use("t.get(k).copied().unwrap_or_else", "t"),
            MapUse::Escape
        );
        // A bare `.unwrap()` after `.get(k)` panics rather than bounding,
        // so we refuse to treat it as safe.  The caller would need a proven
        // `.contains_key` guard; that is out of scope here.
        assert_eq!(classify_map_use("t.get(k).unwrap", "t"), MapUse::Escape);
    }

    #[test]
    fn classify_rejects_other_receiver() {
        // `other.insert` does not belong to `table`, receiver mismatch.
        assert_eq!(classify_map_use("other.insert", "table"), MapUse::Escape);
    }

    #[test]
    fn scan_past_balanced_parens_basic() {
        assert_eq!(scan_past_balanced_parens("foo)").unwrap_or(""), "");
        assert_eq!(scan_past_balanced_parens("foo).bar").unwrap_or(""), ".bar");
        assert_eq!(
            scan_past_balanced_parens("foo(bar)baz).x").unwrap_or(""),
            ".x"
        );
        assert!(scan_past_balanced_parens("no-close").is_none());
    }

    #[test]
    fn non_rust_lang_returns_empty() {
        use petgraph::Graph;
        let body = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };
        let cfg: Cfg = Graph::new();
        let const_values = HashMap::new();
        let result = analyze(&body, &cfg, Some(Lang::Java), &const_values);
        assert!(result.is_empty());
    }
}
