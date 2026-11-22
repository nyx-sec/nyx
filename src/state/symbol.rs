use crate::cfg::Cfg;
use petgraph::visit::IntoNodeReferences;
use rustc_hash::FxHashMap;

/// Cheap `Copy` handle into a [`SymbolInterner`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SymbolId(pub(crate) u32);

/// Function-scope discriminator for symbol interning.
///
/// This provides **function-level isolation only**, not full lexical/block
/// scope modeling.  Variables in different functions with the same name get
/// distinct [`SymbolId`]s.  Top-level / module-scope code uses `scope: None`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ScopedKey {
    scope: Option<String>,
    name: String,
}

/// Per-analysis interner: maps variable names ↔ [`SymbolId`].
///
/// Built once from CFG node `defines`/`uses`, reused throughout analysis.
/// Two construction modes:
/// - [`from_cfg`](Self::from_cfg): flat (unscoped) interning, used by taint/SSA pipeline
/// - [`from_cfg_scoped`](Self::from_cfg_scoped): function-scoped interning, used by state analysis
#[derive(Default)]
pub struct SymbolInterner {
    /// `FxHashMap` (rustc_hash) replaces stdlib SipHash: this map is probed on
    /// every `intern_scoped` / `get_scoped` call during SSA lowering (one of
    /// the hottest paths), keyed on short variable-name strings.  Never
    /// iterated — `SymbolId` assignment order is driven solely by `to_str`
    /// (push order) — so the faster deterministic hasher is output-invariant.
    to_id: FxHashMap<ScopedKey, SymbolId>,
    /// Clean variable names for user-facing resolution (not scoped keys).
    to_str: Vec<String>,
}

impl SymbolInterner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a name with function-scope context, returning its stable [`SymbolId`].
    ///
    /// The `scope` parameter is typically `NodeInfo::enclosing_func`.  `None`
    /// means top-level / module scope.  The stored name (returned by
    /// [`resolve`](Self::resolve)) is always the clean variable name, not the
    /// scoped key.
    pub fn intern_scoped(&mut self, scope: Option<&str>, name: &str) -> SymbolId {
        // Member expressions (e.g. `this.fd`, `self.conn`) are shared class/
        // instance state, keep them in the global (None) scope so that
        // `open()` and `close()` methods can track the same resource symbol.
        // Only plain local variables get function-scoped isolation.
        let effective_scope = if name.contains('.') { None } else { scope };
        let key = ScopedKey {
            scope: effective_scope.map(|s| s.to_owned()),
            name: name.to_owned(),
        };
        if let Some(&id) = self.to_id.get(&key) {
            return id;
        }
        let id = SymbolId(self.to_str.len() as u32);
        self.to_str.push(name.to_owned());
        self.to_id.insert(key, id);
        id
    }

    /// Look up a name by function scope without interning it.
    pub fn get_scoped(&self, scope: Option<&str>, name: &str) -> Option<SymbolId> {
        let effective_scope = if name.contains('.') { None } else { scope };
        let key = ScopedKey {
            scope: effective_scope.map(|s| s.to_owned()),
            name: name.to_owned(),
        };
        self.to_id.get(&key).copied()
    }

    /// Intern a name (unscoped, equivalent to `intern_scoped(None, name)`).
    ///
    /// Used by the taint/SSA pipeline and unit tests that don't need
    /// function-scope isolation.
    pub fn intern(&mut self, name: &str) -> SymbolId {
        self.intern_scoped(None, name)
    }

    /// Look up a name without interning it (unscoped, equivalent to
    /// `get_scoped(None, name)`).
    pub fn get(&self, name: &str) -> Option<SymbolId> {
        self.get_scoped(None, name)
    }

    /// Resolve an id back to its clean variable name.
    pub fn resolve(&self, id: SymbolId) -> &str {
        &self.to_str[id.0 as usize]
    }

    /// Number of interned symbols.
    pub fn len(&self) -> usize {
        self.to_str.len()
    }

    /// Whether the interner is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.to_str.is_empty()
    }

    /// Build from a CFG with flat (unscoped) interning.
    ///
    /// Every `defines`/`uses` variable is interned without function-scope
    /// context.  Used by the taint/SSA pipeline where SSA value numbering
    /// already provides per-function scoping.
    pub fn from_cfg(cfg: &Cfg) -> Self {
        let mut interner = Self::new();
        for (_idx, info) in cfg.node_references() {
            if let Some(ref d) = info.taint.defines {
                interner.intern(d);
            }
            for u in &info.taint.uses {
                interner.intern(u);
            }
            for e in &info.elem_reads {
                interner.intern(e);
            }
        }
        interner
    }

    /// Build from a CFG with function-scoped interning.
    ///
    /// Variables are keyed by `(enclosing_func, name)` so that same-name
    /// variables in different functions get distinct [`SymbolId`]s.  This is
    /// the constructor used by the state analysis pipeline (resource lifecycle,
    /// auth).
    pub fn from_cfg_scoped(cfg: &Cfg) -> Self {
        let mut interner = Self::new();
        for (_idx, info) in cfg.node_references() {
            let scope = info.ast.enclosing_func.as_deref();
            if let Some(ref d) = info.taint.defines {
                interner.intern_scoped(scope, d);
            }
            // Secondary defines (Go `f, err := os.Open(p)` binds `err`
            // here) so the error-companion pairing can name them.
            for d in &info.taint.extra_defines {
                interner.intern_scoped(scope, d);
            }
            for u in &info.taint.uses {
                interner.intern_scoped(scope, u);
            }
        }
        interner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_resolve_roundtrip() {
        let mut interner = SymbolInterner::new();
        let a = interner.intern("foo");
        let b = interner.intern("bar");
        let a2 = interner.intern("foo");

        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert_eq!(interner.resolve(a), "foo");
        assert_eq!(interner.resolve(b), "bar");
    }

    #[test]
    fn get_returns_none_for_unknown() {
        let interner = SymbolInterner::new();
        assert!(interner.get("missing").is_none());
    }

    #[test]
    fn len_tracks_unique_symbols() {
        let mut interner = SymbolInterner::new();
        interner.intern("a");
        interner.intern("b");
        interner.intern("a"); // duplicate
        assert_eq!(interner.len(), 2);
    }

    #[test]
    fn scoped_different_funcs_get_different_ids() {
        let mut interner = SymbolInterner::new();
        let a = interner.intern_scoped(Some("funcA"), "f");
        let b = interner.intern_scoped(Some("funcB"), "f");
        assert_ne!(
            a, b,
            "same variable name in different functions must get different IDs"
        );
    }

    #[test]
    fn scoped_same_func_same_id() {
        let mut interner = SymbolInterner::new();
        let a = interner.intern_scoped(Some("funcA"), "f");
        let a2 = interner.intern_scoped(Some("funcA"), "f");
        assert_eq!(a, a2);
    }

    #[test]
    fn scoped_resolve_returns_clean_name() {
        let mut interner = SymbolInterner::new();
        let id = interner.intern_scoped(Some("my_function"), "resource");
        assert_eq!(
            interner.resolve(id),
            "resource",
            "resolve must return clean name, not scoped key"
        );
    }

    #[test]
    fn unscoped_get_does_not_find_scoped() {
        let mut interner = SymbolInterner::new();
        interner.intern_scoped(Some("funcA"), "f");
        assert!(
            interner.get("f").is_none(),
            "unscoped get must not find a function-scoped entry"
        );
    }

    #[test]
    fn scoped_get_does_not_find_unscoped() {
        let mut interner = SymbolInterner::new();
        interner.intern("f");
        assert!(
            interner.get_scoped(Some("funcA"), "f").is_none(),
            "scoped get must not find an unscoped entry"
        );
    }

    #[test]
    fn toplevel_scope_is_none() {
        let mut interner = SymbolInterner::new();
        let a = interner.intern_scoped(None, "x");
        let b = interner.intern("x");
        assert_eq!(
            a, b,
            "intern() and intern_scoped(None, ..) must produce the same ID"
        );
    }

    #[test]
    fn member_expressions_shared_across_methods() {
        let mut interner = SymbolInterner::new();
        // this.fd in open() and this.fd in close() must share the same ID
        // because member expressions are instance/class state, not locals.
        let a = interner.intern_scoped(Some("open"), "this.fd");
        let b = interner.intern_scoped(Some("close"), "this.fd");
        assert_eq!(
            a, b,
            "member expressions (containing '.') must be shared across function scopes"
        );
    }

    #[test]
    fn plain_locals_isolated_across_methods() {
        let mut interner = SymbolInterner::new();
        let a = interner.intern_scoped(Some("open"), "fd");
        let b = interner.intern_scoped(Some("close"), "fd");
        assert_ne!(
            a, b,
            "plain local variables must be isolated across function scopes"
        );
    }
}
