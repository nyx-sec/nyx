use super::lattice::Lattice;
use super::symbol::SymbolId;
use bitflags::bitflags;
use std::collections::{BTreeSet, HashMap, HashSet};

// ── ResourceLifecycle ────────────────────────────────────────────────────

bitflags! {
    /// Bitset of possible lifecycle states for a single resource handle.
    ///
    /// Join = bitwise OR (a variable may be in multiple states across paths).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ResourceLifecycle: u8 {
        const UNINIT = 0b0001;
        const OPEN   = 0b0010;
        const CLOSED = 0b0100;
        const MOVED  = 0b1000;
    }
}

impl Lattice for ResourceLifecycle {
    fn bot() -> Self {
        ResourceLifecycle::empty()
    }

    fn join(&self, other: &Self) -> Self {
        *self | *other
    }

    fn leq(&self, other: &Self) -> bool {
        self.intersection(*other) == *self
    }
}

// ── ResourceDomainState ──────────────────────────────────────────────────

/// Maps interned variable IDs to their lifecycle bitsets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceDomainState {
    pub vars: HashMap<SymbolId, ResourceLifecycle>,
}

impl ResourceDomainState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, sym: SymbolId) -> ResourceLifecycle {
        self.vars
            .get(&sym)
            .copied()
            .unwrap_or(ResourceLifecycle::empty())
    }

    pub fn set(&mut self, sym: SymbolId, state: ResourceLifecycle) {
        self.vars.insert(sym, state);
    }
}

impl Lattice for ResourceDomainState {
    fn bot() -> Self {
        Self::new()
    }

    fn join(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        for (&sym, &other_lc) in &other.vars {
            let entry = merged.vars.entry(sym).or_insert(ResourceLifecycle::empty());
            *entry = entry.join(&other_lc);
        }
        merged
    }

    fn leq(&self, other: &Self) -> bool {
        for (&sym, &self_lc) in &self.vars {
            let other_lc = other.get(sym);
            if !self_lc.leq(&other_lc) {
                return false;
            }
        }
        true
    }
}

// ── AuthLevel ────────────────────────────────────────────────────────────

/// Simple ordered lattice for path authentication state.
///
/// Bot = `Unauthed`. Join = `min` (conservative: if any path is unauthed,
/// the joined state is unauthed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuthLevel {
    Unauthed,
    Authed,
    Admin,
}

impl Lattice for AuthLevel {
    fn bot() -> Self {
        AuthLevel::Unauthed
    }

    fn join(&self, other: &Self) -> Self {
        // Conservative: take the minimum (least privileged)
        (*self).min(*other)
    }

    fn leq(&self, other: &Self) -> bool {
        // Higher auth subsumes lower: Unauthed ⊑ Authed ⊑ Admin
        // In our lattice, join = min, so leq means self >= other
        *self >= *other
    }
}

// ── AuthDomainState ──────────────────────────────────────────────────────

/// Path auth level + per-variable validation bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthDomainState {
    pub auth_level: AuthLevel,
    pub validated: HashSet<SymbolId>,
}

impl Default for AuthDomainState {
    fn default() -> Self {
        Self {
            auth_level: AuthLevel::Unauthed,
            validated: HashSet::new(),
        }
    }
}

impl AuthDomainState {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Lattice for AuthDomainState {
    fn bot() -> Self {
        Self::new()
    }

    fn join(&self, other: &Self) -> Self {
        Self {
            auth_level: self.auth_level.join(&other.auth_level),
            // Only validated on ALL paths counts
            validated: self
                .validated
                .intersection(&other.validated)
                .copied()
                .collect(),
        }
    }

    fn leq(&self, other: &Self) -> bool {
        self.auth_level.leq(&other.auth_level) && self.validated.is_superset(&other.validated)
    }
}

// ── ProductState ─────────────────────────────────────────────────────────

/// Per-chain-receiver proxy tracking entry.
///
/// The state machine carries this for every chained-receiver resource
/// proxy call (`c.mu.Lock()`, `c.writer.header.set(...)`).  Stored in
/// [`ProductState::chain_proxies`] keyed by the joined chain text
/// (e.g. `"c.mu"`, `"c.writer.header"`) so distinct field projections
/// of the same chain root are tracked independently.
///
/// Chain-keyed proxy state is the DTO replacement for the single-dot
/// band-aid that conservatively dropped chain receivers entirely, chain
/// receivers are now first-class, semantically distinct from their root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainProxyState {
    pub lifecycle: ResourceLifecycle,
    pub class_group: crate::cfg::BodyId,
    pub acquire_span: (usize, usize),
}

/// Go error companions: `(err, resource)` pairs bound by one acquire
/// (`f, err := os.Open(p)`) whose `err` and resource have not been reassigned
/// since, on every path reaching the node.  On the branch where such an `err`
/// is non-nil the acquire failed and the resource is the zero value, so the
/// resource passes drop its OPEN state there.
///
/// A must-fact: join is intersection, so a pair survives a merge only when it
/// holds on every incoming path.  `None` is the join identity ("no path has
/// reached this node yet"), which keeps `bot()` a true identity for
/// intersection; [`ProductState::initial`] starts from the empty set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ErrCompanions(Option<BTreeSet<(SymbolId, SymbolId)>>);

impl ErrCompanions {
    pub fn empty() -> Self {
        Self(Some(BTreeSet::new()))
    }

    /// Record that `resource` was acquired together with `err`.
    pub fn bind(&mut self, err: SymbolId, resource: SymbolId) {
        self.0
            .get_or_insert_with(BTreeSet::new)
            .insert((err, resource));
    }

    /// Drop every pair that mentions `sym` on either side (it was
    /// reassigned, so the pairing no longer describes the current values).
    pub fn kill(&mut self, sym: SymbolId) {
        if let Some(pairs) = self.0.as_mut() {
            pairs.retain(|&(e, r)| e != sym && r != sym);
        }
    }

    /// Resources currently paired with `err`.
    pub fn resources_of(&self, err: SymbolId) -> impl Iterator<Item = SymbolId> + '_ {
        self.0
            .iter()
            .flat_map(|pairs| pairs.iter())
            .filter(move |&&(e, _)| e == err)
            .map(|&(_, r)| r)
    }
}

impl Lattice for ErrCompanions {
    fn bot() -> Self {
        Self(None)
    }

    fn join(&self, other: &Self) -> Self {
        match (&self.0, &other.0) {
            (None, _) => other.clone(),
            (_, None) => self.clone(),
            (Some(a), Some(b)) => Self(Some(a.intersection(b).copied().collect())),
        }
    }

    fn leq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(a), Some(b)) => a.is_superset(b),
        }
    }
}

/// Composable product of resource and auth domains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductState {
    pub resource: ResourceDomainState,
    pub auth: AuthDomainState,
    /// Maps receiver symbol → class group (BodyId) for proxy resource tracking.
    /// Populated when a proxy acquire fires; checked during proxy release to
    /// ensure the same class context.
    pub receiver_class_group: HashMap<SymbolId, crate::cfg::BodyId>,
    /// Maps receiver symbol → original acquire span for proxy resources.
    /// Used by `extract_findings` to attribute leaks to the original resource
    /// operation (e.g., fs.openSync at line 7) rather than the proxy call.
    pub proxy_acquire_spans: HashMap<SymbolId, (usize, usize)>,
    /// Maps a symbol holding an OPEN handle to the span of the node that
    /// acquired it.  An alias move (`q = p`) carries the span to the new
    /// owner.  `extract_findings` reads it to place a leak at the real acquire
    /// instead of searching the CFG by variable name.  Joins keep the earlier
    /// span so the merge is order-independent.
    pub acquire_spans: HashMap<SymbolId, (usize, usize)>,
    /// Maps a name bound to a sub-object address or offset of a handle
    /// (`s = (char *)sh + hdrlen`, `base = &iter->base`) to the handle's
    /// symbol.  The handle keeps its own state; a release, hand-off or return
    /// of the alias is read as one of the handle.  Joins union the entries.
    pub sub_aliases: HashMap<SymbolId, SymbolId>,
    /// Per-chain-receiver proxy tracking, keyed by joined chain text
    /// (`"c.mu"`, `"c.writer.header"`). Each chain receiver has its own
    /// lifecycle, class group, and acquire span, independent of both
    /// the chain root and any other chain.
    ///
    /// Tracking-only: chain receivers that remain OPEN at exit are NOT
    /// promoted to leak findings.
    pub chain_proxies: HashMap<String, ChainProxyState>,
    /// Go `(err, resource)` acquire pairs still valid at this node.
    pub err_companions: ErrCompanions,
}

impl ProductState {
    pub fn initial() -> Self {
        Self {
            resource: ResourceDomainState::new(),
            auth: AuthDomainState::new(),
            receiver_class_group: HashMap::new(),
            proxy_acquire_spans: HashMap::new(),
            acquire_spans: HashMap::new(),
            sub_aliases: HashMap::new(),
            chain_proxies: HashMap::new(),
            err_companions: ErrCompanions::empty(),
        }
    }
}

impl Lattice for ProductState {
    fn bot() -> Self {
        Self {
            resource: ResourceDomainState::bot(),
            auth: AuthDomainState::bot(),
            receiver_class_group: HashMap::new(),
            proxy_acquire_spans: HashMap::new(),
            acquire_spans: HashMap::new(),
            sub_aliases: HashMap::new(),
            chain_proxies: HashMap::new(),
            err_companions: ErrCompanions::bot(),
        }
    }

    fn join(&self, other: &Self) -> Self {
        // Merge proxy tracking: union of mappings
        let mut class_group = self.receiver_class_group.clone();
        class_group.extend(other.receiver_class_group.iter());
        let mut proxy_spans = self.proxy_acquire_spans.clone();
        proxy_spans.extend(other.proxy_acquire_spans.iter());
        let mut acquire_spans = self.acquire_spans.clone();
        for (sym, span) in &other.acquire_spans {
            acquire_spans
                .entry(*sym)
                .and_modify(|e| *e = (*e).min(*span))
                .or_insert(*span);
        }
        let mut sub_aliases = self.sub_aliases.clone();
        for (alias, root) in &other.sub_aliases {
            sub_aliases
                .entry(*alias)
                .and_modify(|e| *e = (*e).min(*root))
                .or_insert(*root);
        }
        // Chain proxies: union, with lifecycle joined per-key so an OPEN
        // entry on one path remains OPEN if joined with a missing entry
        // on another path (matches the existing receiver_class_group
        // semantics).  Last-writer-wins for class_group / acquire_span:
        // both are stable per chain receiver in practice (a chain root +
        // field path is monomorphic), so the conflict cases collapse.
        let mut chain = self.chain_proxies.clone();
        for (key, other_state) in &other.chain_proxies {
            chain
                .entry(key.clone())
                .and_modify(|e| {
                    e.lifecycle = e.lifecycle.join(&other_state.lifecycle);
                })
                .or_insert_with(|| other_state.clone());
        }
        Self {
            resource: self.resource.join(&other.resource),
            auth: self.auth.join(&other.auth),
            receiver_class_group: class_group,
            proxy_acquire_spans: proxy_spans,
            acquire_spans,
            sub_aliases,
            chain_proxies: chain,
            err_companions: self.err_companions.join(&other.err_companions),
        }
    }

    fn leq(&self, other: &Self) -> bool {
        self.resource.leq(&other.resource)
            && self.auth.leq(&other.auth)
            && self.err_companions.leq(&other.err_companions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_lifecycle_join_is_or() {
        let a = ResourceLifecycle::OPEN;
        let b = ResourceLifecycle::CLOSED;
        assert_eq!(
            a.join(&b),
            ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED
        );
    }

    #[test]
    fn resource_lifecycle_bot_identity() {
        let a = ResourceLifecycle::OPEN;
        assert_eq!(a.join(&ResourceLifecycle::bot()), a);
    }

    #[test]
    fn resource_lifecycle_leq() {
        let a = ResourceLifecycle::OPEN;
        let b = ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED;
        assert!(a.leq(&b));
        assert!(!b.leq(&a));
    }

    #[test]
    fn resource_domain_join_merges_keys() {
        let mut a = ResourceDomainState::new();
        let mut b = ResourceDomainState::new();
        let sym_x = SymbolId(0);
        let sym_y = SymbolId(1);

        a.set(sym_x, ResourceLifecycle::OPEN);
        b.set(sym_x, ResourceLifecycle::CLOSED);
        b.set(sym_y, ResourceLifecycle::OPEN);

        let joined = a.join(&b);
        assert_eq!(
            joined.get(sym_x),
            ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED
        );
        assert_eq!(joined.get(sym_y), ResourceLifecycle::OPEN);
    }

    #[test]
    fn auth_level_join_is_min() {
        assert_eq!(
            AuthLevel::Admin.join(&AuthLevel::Unauthed),
            AuthLevel::Unauthed
        );
        assert_eq!(AuthLevel::Authed.join(&AuthLevel::Admin), AuthLevel::Authed);
        assert_eq!(
            AuthLevel::Authed.join(&AuthLevel::Authed),
            AuthLevel::Authed
        );
    }

    #[test]
    fn auth_domain_join_intersects_validated() {
        let sym_a = SymbolId(0);
        let sym_b = SymbolId(1);
        let sym_c = SymbolId(2);

        let a = AuthDomainState {
            auth_level: AuthLevel::Authed,
            validated: [sym_a, sym_b].into_iter().collect(),
        };
        let b = AuthDomainState {
            auth_level: AuthLevel::Admin,
            validated: [sym_b, sym_c].into_iter().collect(),
        };

        let joined = a.join(&b);
        assert_eq!(joined.auth_level, AuthLevel::Authed);
        assert_eq!(joined.validated, [sym_b].into_iter().collect());
    }

    #[test]
    fn err_companions_join_is_intersection_with_bot_identity() {
        let (err, f, g) = (SymbolId(0), SymbolId(1), SymbolId(2));
        let mut a = ErrCompanions::empty();
        a.bind(err, f);
        a.bind(err, g);
        let mut b = ErrCompanions::empty();
        b.bind(err, f);

        let joined = a.join(&b);
        assert_eq!(joined.resources_of(err).collect::<Vec<_>>(), vec![f]);
        assert_eq!(a.join(&ErrCompanions::bot()), a);
        assert_eq!(ErrCompanions::bot().join(&a), a);
        assert!(a.leq(&b), "more pairs is more precise");
        assert!(!b.leq(&a));

        // A path that never bound anything empties the meet.
        assert_eq!(a.join(&ErrCompanions::empty()).resources_of(err).count(), 0);
    }

    #[test]
    fn err_companions_kill_drops_both_sides() {
        let (err, f, other) = (SymbolId(0), SymbolId(1), SymbolId(2));
        let mut a = ErrCompanions::empty();
        a.bind(err, f);
        a.kill(other);
        assert_eq!(a.resources_of(err).count(), 1);
        a.kill(err);
        assert_eq!(a.resources_of(err).count(), 0);

        let mut b = ErrCompanions::empty();
        b.bind(err, f);
        b.kill(f);
        assert_eq!(b.resources_of(err).count(), 0);
    }

    #[test]
    fn product_state_join() {
        let a = ProductState::initial();
        let b = ProductState::initial();
        let joined = a.join(&b);
        assert_eq!(joined, ProductState::initial());
    }

    #[test]
    fn may_must_leak_semantics() {
        // Must-leak: OPEN only
        let must_leak = ResourceLifecycle::OPEN;
        assert!(must_leak.contains(ResourceLifecycle::OPEN));
        assert!(!must_leak.contains(ResourceLifecycle::CLOSED));
        assert!(!must_leak.contains(ResourceLifecycle::MOVED));

        // May-leak: OPEN | CLOSED (some paths close, some don't)
        let may_leak = ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED;
        assert!(may_leak.contains(ResourceLifecycle::OPEN));
        assert!(may_leak.contains(ResourceLifecycle::CLOSED));

        // No leak: CLOSED only
        let no_leak = ResourceLifecycle::CLOSED;
        assert!(!no_leak.contains(ResourceLifecycle::OPEN));
        assert!(no_leak.contains(ResourceLifecycle::CLOSED));
    }

    // SymbolId is a newtype used in domain tests; ensure it's Copy
    #[test]
    fn symbol_id_is_copy() {
        let s = SymbolId(0);
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── Lattice law checks on the real domains ─────────────────────
    //
    // The trait-level `lattice.rs` tests use a synthetic `Three` lattice;
    // the laws also need to hold on the *actual* impls used by the
    // engine. A change to ResourceLifecycle's bitset semantics or to
    // AuthLevel's ordering could quietly break commutativity /
    // associativity / idempotence, these tests pin those properties.

    #[test]
    fn resource_lifecycle_join_laws() {
        let vals = [
            ResourceLifecycle::empty(),
            ResourceLifecycle::UNINIT,
            ResourceLifecycle::OPEN,
            ResourceLifecycle::CLOSED,
            ResourceLifecycle::MOVED,
            ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED,
            ResourceLifecycle::all(),
        ];
        for a in &vals {
            // Idempotence: a ⊔ a = a
            assert_eq!(a.join(a), *a, "idempotence broken on {a:?}");
            // Bot identity: a ⊔ ⊥ = a
            assert_eq!(a.join(&ResourceLifecycle::bot()), *a);
            for b in &vals {
                // Commutativity: a ⊔ b = b ⊔ a
                assert_eq!(a.join(b), b.join(a), "commutativity broken ({a:?},{b:?})");
                // leq consistent with join: a ⊑ b iff a ⊔ b = b
                let consistent = a.leq(b) == (a.join(b) == *b);
                assert!(consistent, "leq/join consistency broken ({a:?} ⊑ {b:?})");
                for c in &vals {
                    // Associativity
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(&b.join(c)),
                        "associativity broken ({a:?},{b:?},{c:?})"
                    );
                }
            }
        }
    }

    /// `AuthLevel` satisfies idempotence, commutativity, and associativity
    /// of `join` (which is `min` of the privilege ordering). It does NOT
    /// satisfy the `Lattice` trait's bot-identity law, see the explicit
    /// `auth_level_bot_is_absorbing_not_identity` test below for a
    /// rationale and a regression guard.
    #[test]
    fn auth_level_join_associative_commutative_idempotent() {
        let vals = [AuthLevel::Unauthed, AuthLevel::Authed, AuthLevel::Admin];
        for a in &vals {
            assert_eq!(a.join(a), *a, "AuthLevel idempotence broken on {a:?}");
            for b in &vals {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "AuthLevel commutativity ({a:?},{b:?})"
                );
                for c in &vals {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(&b.join(c)),
                        "AuthLevel associativity ({a:?},{b:?},{c:?})"
                    );
                }
            }
        }
    }

    /// **Audit finding pinned as a regression guard.**
    ///
    /// `AuthLevel` deliberately violates the `Lattice` trait's bot-identity
    /// law (`a ⊔ ⊥ = a`). The trait says `bot()` is the join identity, but:
    ///
    ///   * `bot()` returns `Unauthed`
    ///   * `join` is `min` over the ordering `Unauthed < Authed < Admin`
    ///   * therefore `Admin.join(Unauthed) == Unauthed`, not `Admin`
    ///
    /// In other words, `Unauthed` is the *absorbing* element of the join,
    /// not the identity, the algebraic dual of what the trait expects.
    ///
    /// This is intentional for security: if any incoming path is unauthed,
    /// the merged state must be unauthed (the conservative baseline). The
    /// trait contract violation matters only if the dataflow engine ever
    /// joins `bot()` with a non-bot reachable state from a different path
    /// (e.g. for an unreachable predecessor); in the current engine such
    /// nodes are skipped, so the violation is observably benign, but
    /// documenting it here prevents an accidental "fix" that flips
    /// `bot()` to `Admin` and silently elevates auth across all merges.
    #[test]
    fn auth_level_bot_is_absorbing_not_identity() {
        assert_eq!(AuthLevel::bot(), AuthLevel::Unauthed);
        // Absorbing: Admin ⊔ Unauthed = Unauthed (conservative).
        assert_eq!(
            AuthLevel::Admin.join(&AuthLevel::Unauthed),
            AuthLevel::Unauthed,
            "Unauthed must absorb Admin under min-join (conservative security)"
        );
        // NOT identity: Admin ⊔ bot ≠ Admin (would be the trait law).
        assert_ne!(
            AuthLevel::Admin.join(&AuthLevel::bot()),
            AuthLevel::Admin,
            "if this passes, AuthLevel::bot() was changed — re-audit security implications"
        );
    }

    /// `leq` for AuthLevel is "at least as privileged": Admin ⊑ Authed ⊑
    /// Unauthed in the privilege ordering. The trait law `a.leq(b) iff
    /// a.join(b) == b` therefore must read `b absorbs a`, since join is
    /// min. Verify the consistency on every pair.
    #[test]
    fn auth_level_leq_consistent_with_join() {
        let vals = [AuthLevel::Unauthed, AuthLevel::Authed, AuthLevel::Admin];
        for a in &vals {
            for b in &vals {
                assert_eq!(
                    a.leq(b),
                    a.join(b) == *b,
                    "leq/join inconsistent on ({a:?}, {b:?})"
                );
            }
        }
    }

    /// `AuthDomainState::join` keeps a variable as `validated` only if
    /// it was validated on *every* incoming path. A variable validated
    /// on one branch but not the other must be dropped, otherwise an
    /// auth bypass on one path silently authorises sinks on the merge
    /// path.
    #[test]
    fn auth_domain_join_drops_partially_validated() {
        let sym_only_a = SymbolId(10);
        let sym_only_b = SymbolId(11);

        let a = AuthDomainState {
            auth_level: AuthLevel::Authed,
            validated: [sym_only_a].into_iter().collect(),
        };
        let b = AuthDomainState {
            auth_level: AuthLevel::Authed,
            validated: [sym_only_b].into_iter().collect(),
        };
        let j = a.join(&b);
        assert!(
            j.validated.is_empty(),
            "validated set must drop vars not validated on all paths"
        );
    }

    /// ProductState join must combine resource OPEN | CLOSED across
    /// branches (may-leak), keep min-auth, and union the proxy maps.
    /// This exercises the non-trivial join (the existing test only
    /// joins two identical initial states).
    #[test]
    fn product_state_join_non_trivial() {
        let sym_x = SymbolId(20);
        let sym_y = SymbolId(21);

        let mut a = ProductState::initial();
        a.resource.set(sym_x, ResourceLifecycle::OPEN);
        a.auth.auth_level = AuthLevel::Admin;
        a.auth.validated.insert(sym_y);

        let mut b = ProductState::initial();
        b.resource.set(sym_x, ResourceLifecycle::CLOSED);
        b.auth.auth_level = AuthLevel::Authed;
        b.auth.validated.insert(sym_y);

        let j = a.join(&b);
        assert_eq!(
            j.resource.get(sym_x),
            ResourceLifecycle::OPEN | ResourceLifecycle::CLOSED,
            "may-leak: OPEN on one path, CLOSED on the other"
        );
        assert_eq!(j.auth.auth_level, AuthLevel::Authed, "join takes min auth");
        assert!(
            j.auth.validated.contains(&sym_y),
            "var validated on both paths must survive"
        );
    }
}
