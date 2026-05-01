use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::ir::*;

/// Maximum members per alias group to bound analysis cost.
const MAX_ALIAS_GROUP_SIZE: usize = 16;

/// Result of base-variable alias analysis.
///
/// Maps variable base names that are known to reference the same object.
/// Two names in the same group are must-aliases: a copy `b = a` (with no
/// semantic labels) means `b` and `a` reference the same value, so field
/// paths like `b.data` and `a.data` are interchangeable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaseAliasResult {
    /// base_name → canonical name.  All aliases map to the same canonical.
    canonical: HashMap<String, String>,
    /// canonical_name → all member base names (including the canonical itself).
    members: HashMap<String, SmallVec<[String; 4]>>,
}

impl BaseAliasResult {
    /// An empty result (no aliases detected).
    pub fn empty() -> Self {
        Self {
            canonical: HashMap::new(),
            members: HashMap::new(),
        }
    }

    /// True when no aliases were found.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Get all must-alias base names for `base` (including itself).
    /// Returns `None` if the name has no known aliases.
    pub fn aliases_of(&self, base: &str) -> Option<&[String]> {
        let canon = self.canonical.get(base)?;
        self.members.get(canon).map(|v| v.as_slice())
    }

    /// Check if two base names are must-aliases.
    pub fn are_aliases(&self, a: &str, b: &str) -> bool {
        if a == b {
            return true;
        }
        match (self.canonical.get(a), self.canonical.get(b)) {
            (Some(ca), Some(cb)) => ca == cb,
            _ => false,
        }
    }
}

/// Compute base-variable alias groups from the copy propagation replacement map.
///
/// For each entry `(dst_val, src_val)` where copy prop replaced `dst` with
/// `src`, looks up the original variable names.  If both are plain identifiers
/// (no dots, i.e. not field paths), they are registered as base aliases.
/// Transitive closure is computed so `b = a; c = b` yields group `{a, b, c}`.
pub fn compute_base_aliases(
    copy_map: &HashMap<SsaValue, SsaValue>,
    body: &SsaBody,
) -> BaseAliasResult {
    if copy_map.is_empty() {
        return BaseAliasResult::empty();
    }

    // Union-Find for transitive closure (string-keyed, small N).
    let mut parent: HashMap<String, String> = HashMap::new();

    fn find(parent: &mut HashMap<String, String>, x: &str) -> String {
        if !parent.contains_key(x) {
            return x.to_string();
        }
        let mut root = x.to_string();
        // Chase to root (with iteration cap for safety).
        for _ in 0..100 {
            match parent.get(&root) {
                Some(p) if p != &root => root = p.clone(),
                _ => break,
            }
        }
        // Path compression.
        let mut cur = x.to_string();
        for _ in 0..100 {
            match parent.get(&cur) {
                Some(p) if p != &root => {
                    let next = p.clone();
                    parent.insert(cur, root.clone());
                    cur = next;
                }
                _ => break,
            }
        }
        root
    }

    fn union(parent: &mut HashMap<String, String>, a: &str, b: &str) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            // Arbitrary root choice, alphabetically smaller becomes root
            // for determinism.
            if ra < rb {
                parent.insert(rb, ra);
            } else {
                parent.insert(ra, rb);
            }
        }
    }

    // Collect alias pairs from the copy map.
    for (&dst, &src) in copy_map {
        let dst_idx = dst.0 as usize;
        let src_idx = src.0 as usize;
        if dst_idx >= body.value_defs.len() || src_idx >= body.value_defs.len() {
            continue;
        }

        let dst_name = match &body.value_defs[dst_idx].var_name {
            Some(n) => n.as_str(),
            None => continue,
        };
        let src_name = match &body.value_defs[src_idx].var_name {
            Some(n) => n.as_str(),
            None => continue,
        };

        // Only alias plain idents, dotted paths (field accesses) are tracked
        // independently in SSA and handled by field-aware suppression.
        if dst_name.contains('.') || src_name.contains('.') {
            continue;
        }

        // Skip self-aliases.
        if dst_name == src_name {
            continue;
        }

        // Ensure both exist in the parent map.
        parent
            .entry(dst_name.to_string())
            .or_insert_with(|| dst_name.to_string());
        parent
            .entry(src_name.to_string())
            .or_insert_with(|| src_name.to_string());

        union(&mut parent, dst_name, src_name);
    }

    if parent.is_empty() {
        return BaseAliasResult::empty();
    }

    // Build groups from union-find.
    let mut groups: HashMap<String, SmallVec<[String; 4]>> = HashMap::new();
    let all_names: Vec<String> = parent.keys().cloned().collect();
    for name in &all_names {
        let root = find(&mut parent, name);
        groups.entry(root).or_default().push(name.clone());
    }

    // Remove singleton groups (no aliases) and enforce size limit.
    groups.retain(|_, members| members.len() > 1);
    for members in groups.values_mut() {
        members.sort();
        members.truncate(MAX_ALIAS_GROUP_SIZE);
    }

    // Build canonical map.
    let mut canonical: HashMap<String, String> = HashMap::new();
    for (root, members) in &groups {
        for member in members {
            canonical.insert(member.clone(), root.clone());
        }
    }

    BaseAliasResult {
        canonical,
        members: groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::graph::NodeIndex;
    use std::collections::HashMap;

    /// Helper: create a ValueDef with the given var_name.
    fn vdef(name: &str) -> ValueDef {
        ValueDef {
            var_name: Some(name.to_string()),
            cfg_node: NodeIndex::new(0),
            block: BlockId(0),
        }
    }

    fn vdef_none() -> ValueDef {
        ValueDef {
            var_name: None,
            cfg_node: NodeIndex::new(0),
            block: BlockId(0),
        }
    }

    fn make_body(defs: Vec<ValueDef>) -> SsaBody {
        SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: defs,
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        }
    }

    #[test]
    fn test_simple_alias_detection() {
        // v0 = "a", v1 = "b"; copy_map: v1 → v0  ⇒  {a, b}
        let body = make_body(vec![vdef("a"), vdef("b")]);
        let mut copy_map = HashMap::new();
        copy_map.insert(SsaValue(1), SsaValue(0));

        let result = compute_base_aliases(&copy_map, &body);
        assert!(!result.is_empty());
        assert!(result.are_aliases("a", "b"));
        assert!(result.are_aliases("b", "a"));

        let aliases = result.aliases_of("a").unwrap();
        assert_eq!(aliases.len(), 2);
        assert!(aliases.contains(&"a".to_string()));
        assert!(aliases.contains(&"b".to_string()));
    }

    #[test]
    fn test_transitive_aliases() {
        // v0="a", v1="b", v2="c"; copy_map: v1→v0, v2→v1  ⇒  {a, b, c}
        let body = make_body(vec![vdef("a"), vdef("b"), vdef("c")]);
        let mut copy_map = HashMap::new();
        copy_map.insert(SsaValue(1), SsaValue(0));
        copy_map.insert(SsaValue(2), SsaValue(1));

        let result = compute_base_aliases(&copy_map, &body);
        assert!(result.are_aliases("a", "b"));
        assert!(result.are_aliases("b", "c"));
        assert!(result.are_aliases("a", "c"));

        let aliases = result.aliases_of("c").unwrap();
        assert_eq!(aliases.len(), 3);
    }

    #[test]
    fn test_no_alias_for_none_names() {
        // v0=None, v1="b"; copy_map: v1→v0  ⇒  no aliases
        let body = make_body(vec![vdef_none(), vdef("b")]);
        let mut copy_map = HashMap::new();
        copy_map.insert(SsaValue(1), SsaValue(0));

        let result = compute_base_aliases(&copy_map, &body);
        assert!(result.is_empty());
    }

    #[test]
    fn test_dotted_paths_ignored() {
        // v0="a.x", v1="b.x"; copy_map: v1→v0  ⇒  no aliases (dotted)
        let body = make_body(vec![vdef("a.x"), vdef("b.x")]);
        let mut copy_map = HashMap::new();
        copy_map.insert(SsaValue(1), SsaValue(0));

        let result = compute_base_aliases(&copy_map, &body);
        assert!(result.is_empty());
    }

    #[test]
    fn test_alias_group_size_limit() {
        // Create 20 variables all aliased to v0
        let mut defs = vec![vdef("v0")];
        let mut copy_map = HashMap::new();
        for i in 1..20u32 {
            defs.push(vdef(&format!("v{}", i)));
            copy_map.insert(SsaValue(i), SsaValue(0));
        }
        let body = make_body(defs);

        let result = compute_base_aliases(&copy_map, &body);
        // All should be aliases, but group is capped at MAX_ALIAS_GROUP_SIZE
        let aliases = result.aliases_of("v0").unwrap();
        assert_eq!(aliases.len(), MAX_ALIAS_GROUP_SIZE);
    }

    #[test]
    fn test_empty_copy_map() {
        let body = make_body(vec![vdef("a"), vdef("b")]);
        let copy_map = HashMap::new();

        let result = compute_base_aliases(&copy_map, &body);
        assert!(result.is_empty());
    }

    #[test]
    fn test_self_alias_ignored() {
        // v0="a"; copy_map: v0→v0  ⇒  no aliases (self)
        let body = make_body(vec![vdef("a")]);
        let mut copy_map = HashMap::new();
        copy_map.insert(SsaValue(0), SsaValue(0));

        let result = compute_base_aliases(&copy_map, &body);
        assert!(result.is_empty());
    }

    #[test]
    fn test_are_aliases_same_name() {
        let result = BaseAliasResult::empty();
        // Same name is always an alias of itself
        assert!(result.are_aliases("x", "x"));
    }
}
