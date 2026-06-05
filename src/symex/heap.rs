//! Symbolic heap: field-sensitive memory model for symbolic execution.
//!
//! Maps `(HeapObjectId, FieldSlot)` → `SymbolicValue`, enabling the symbolic
//! executor to track taint through object property stores/loads and container
//! operations.  Uses allocation-site identities from `PointsToResult` to
//! distinguish different objects.
//!
//! Design:
#![allow(clippy::new_without_default)]
//! - `FieldSlot::Named` for object properties (per-field precision).
//! - `FieldSlot::Elements` for container contents (flow-insensitive union ,
//!   deliberately lower precision than named fields).
//! - Bounded: `MAX_HEAP_ENTRIES` total, `MAX_FIELDS_PER_OBJECT` per object.
//!   Overflow silently drops the store (conservative: subsequent load → `Unknown`).
//! - `widen()` sets values to `Unknown` but preserves taint flags.
//! - `Clone` for fork-point cloning in multi-path exploration.

use std::collections::{HashMap, HashSet};

use crate::ssa::const_prop::ConstLattice;
use crate::ssa::heap::{HeapObjectId, PointsToResult};
use crate::ssa::ir::{SsaBody, SsaValue};

use super::value::SymbolicValue;

/// Maximum total heap entries across all objects.
const MAX_HEAP_ENTRIES: usize = 64;

/// Maximum named/elements fields tracked per individual object.
/// `Index(*)` entries are bounded separately by [`MAX_TRACKED_INDICES`].
const MAX_FIELDS_PER_OBJECT: usize = 8;

/// Maximum distinct `Index(n)` slots tracked per heap object.
/// When exceeded, all `Index(*)` entries for that object collapse into
/// `Elements` (taint unioned, value set to `Unknown`).
pub const MAX_TRACKED_INDICES: usize = 16;

//  Types

/// Heap key: allocation-site identity + field slot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HeapKey {
    pub object: HeapObjectId,
    pub field: FieldSlot,
}

/// Distinguishes named object fields, per-index array slots, and the
/// element-insensitive fallback.
///
/// Ordering: `Elements` < `Index(0)` < `Index(1)` < … < `Named("a")` < …
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FieldSlot {
    /// Named property: `obj.username`, `config.host`.
    Named(String),
    /// Element-insensitive container contents (flow-insensitive union).
    /// Represents an unknown/dynamic element write that may affect any index.
    /// `push`/`pop` without a known constant index land here.
    Elements,
    /// Concrete per-index slot, proven by constant propagation.
    /// `arr[0]`, `list.get(1)` when the index resolves to a known integer.
    Index(u64),
}

impl PartialOrd for FieldSlot {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FieldSlot {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (self, other) {
            (FieldSlot::Elements, FieldSlot::Elements) => Ordering::Equal,
            (FieldSlot::Elements, _) => Ordering::Less,
            (_, FieldSlot::Elements) => Ordering::Greater,
            (FieldSlot::Index(a), FieldSlot::Index(b)) => a.cmp(b),
            (FieldSlot::Index(_), FieldSlot::Named(_)) => Ordering::Less,
            (FieldSlot::Named(_), FieldSlot::Index(_)) => Ordering::Greater,
            (FieldSlot::Named(a), FieldSlot::Named(b)) => a.cmp(b),
        }
    }
}

/// Metadata recorded at store/load time for witness generation.
///
/// Recorded explicitly rather than reconstructed heuristically from `var_name`
/// strings, ensuring witness accuracy even when heap loads produce SSA values
/// without dotted names.
#[derive(Clone, Debug)]
pub struct FieldAccessRecord {
    /// Receiver expression text: `"user"`, `"req.body"`.
    pub object_name: String,
    /// Field name: `"name"`, `"username"`.
    pub field_name: String,
    /// The SSA value that was stored/loaded.
    pub ssa_value: SsaValue,
}

/// Bounded symbolic heap tracking field-level symbolic values and taint.
///
/// Cloned at fork points during multi-path exploration.  Bounded
/// by `MAX_HEAP_ENTRIES` total entries and `MAX_FIELDS_PER_OBJECT` per
/// object to prevent blowup on object-heavy code.
#[derive(Clone, Debug)]
pub struct SymbolicHeap {
    /// Maps (object, field) → symbolic expression.
    fields: HashMap<HeapKey, SymbolicValue>,
    /// Tracks which heap keys carry taint.
    tainted_keys: HashSet<HeapKey>,
    /// Field access trace for witness generation.
    field_accesses: Vec<FieldAccessRecord>,
}

impl SymbolicHeap {
    /// Create an empty symbolic heap.
    pub fn new() -> Self {
        SymbolicHeap {
            fields: HashMap::new(),
            tainted_keys: HashSet::new(),
            field_accesses: Vec::new(),
        }
    }

    /// Store a symbolic value into a heap field.
    ///
    /// Bounded: silently drops the store if `MAX_HEAP_ENTRIES` or
    /// `MAX_FIELDS_PER_OBJECT` would be exceeded.  `Index(*)` entries are
    /// bounded by [`MAX_TRACKED_INDICES`] per object; overflow collapses all
    /// indexed entries into `Elements`.
    pub fn store(&mut self, key: HeapKey, value: SymbolicValue, tainted: bool) {
        // Index overflow: collapse to Elements if too many distinct indices.
        if let FieldSlot::Index(_) = &key.field {
            if !self.fields.contains_key(&key)
                && self.count_indices_for(key.object) >= MAX_TRACKED_INDICES
            {
                self.collapse_indices_to_elements(key.object);
                // Redirect store to Elements.
                let elem_key = HeapKey {
                    object: key.object,
                    field: FieldSlot::Elements,
                };
                // collapse_indices_to_elements already inserted Elements;
                // update with the new value/taint.
                self.fields.insert(elem_key.clone(), value);
                if tainted {
                    self.tainted_keys.insert(elem_key);
                }
                return;
            }
        }

        // Check bounds (only for new entries).
        if !self.fields.contains_key(&key) {
            if self.fields.len() >= MAX_HEAP_ENTRIES {
                return; // global cap
            }
            // Index entries bypass per-object field cap (bounded by MAX_TRACKED_INDICES).
            if !matches!(key.field, FieldSlot::Index(_))
                && self.fields_for_object(key.object) >= MAX_FIELDS_PER_OBJECT
            {
                return; // per-object cap for Named/Elements
            }
        }

        self.fields.insert(key.clone(), value);
        if tainted {
            self.tainted_keys.insert(key);
        } else {
            self.tainted_keys.remove(&key);
        }
    }

    /// Load the symbolic value for a heap field.
    ///
    /// For `Index(n)`: returns the precise per-index value if present;
    /// otherwise falls back to the `Elements` value (conservative).
    /// Returns `Unknown` if neither is present.
    pub fn load(&self, key: &HeapKey) -> SymbolicValue {
        if let FieldSlot::Index(_) = &key.field {
            // Precise index wins; fall back to Elements.
            if let Some(val) = self.fields.get(key) {
                return val.clone();
            }
            let elem_key = HeapKey {
                object: key.object,
                field: FieldSlot::Elements,
            };
            return self
                .fields
                .get(&elem_key)
                .cloned()
                .unwrap_or(SymbolicValue::Unknown);
        }
        self.fields
            .get(key)
            .cloned()
            .unwrap_or(SymbolicValue::Unknown)
    }

    /// Check if a heap field is tainted.
    ///
    /// For `Index(n)`: returns `true` if either `Index(n)` or `Elements` is
    /// tainted.  An unknown/dynamic store to `Elements` conservatively poisons
    /// all indexed reads.
    pub fn is_tainted(&self, key: &HeapKey) -> bool {
        if self.tainted_keys.contains(key) {
            return true;
        }
        if let FieldSlot::Index(_) = &key.field {
            let elem_key = HeapKey {
                object: key.object,
                field: FieldSlot::Elements,
            };
            return self.tainted_keys.contains(&elem_key);
        }
        false
    }

    /// Iterate over all heap entries (key → value).
    pub fn entries(&self) -> impl Iterator<Item = (&HeapKey, &SymbolicValue)> {
        self.fields.iter()
    }

    /// Record a field access for witness generation.
    pub fn record_access(&mut self, record: FieldAccessRecord) {
        self.field_accesses.push(record);
    }

    /// Get the field access trace for witness generation.
    pub fn field_accesses(&self) -> &[FieldAccessRecord] {
        &self.field_accesses
    }

    /// Compute a compact 64-bit fingerprint of the heap state.
    ///
    /// Used as part of the interprocedural cache key.
    /// Deterministic: entries are sorted by key for consistent hashing.
    pub fn fingerprint(&self) -> u64 {
        if self.fields.is_empty() {
            return 0;
        }
        // Sort keys deterministically using FieldSlot::Ord.
        let mut keys: Vec<&HeapKey> = self.fields.keys().collect();
        keys.sort_by(|a, b| {
            let obj_a = (a.object.0).0;
            let obj_b = (b.object.0).0;
            obj_a.cmp(&obj_b).then_with(|| a.field.cmp(&b.field))
        });

        let mut h: u64 = 0;
        for key in keys {
            let val = &self.fields[key];
            let tainted: u64 = if self.tainted_keys.contains(key) {
                1
            } else {
                0
            };
            let val_tag: u64 = match val {
                SymbolicValue::Concrete(n) => (*n as u64).wrapping_mul(31),
                SymbolicValue::ConcreteStr(s) => {
                    let mut sh: u64 = 0;
                    for b in s.bytes().take(8) {
                        sh = sh.wrapping_mul(31).wrapping_add(b as u64);
                    }
                    sh
                }
                SymbolicValue::Unknown => 0xFF,
                _ => 0xFE,
            };
            // Include field variant discriminant for Index(n) distinction.
            let field_tag: u64 = match &key.field {
                FieldSlot::Elements => 0,
                FieldSlot::Index(n) => 1u64.wrapping_add(*n),
                FieldSlot::Named(_) => 2, // name captured in existing hash via val_tag
            };
            h = h
                .wrapping_mul(67)
                .wrapping_add(val_tag)
                .wrapping_add(tainted << 32)
                .wrapping_add(field_tag << 48);
        }
        h
    }

    /// Widen all heap entries to `Unknown`, preserving taint flags.
    ///
    /// Called at loop heads after bounded unrolling.  `Index(*)` entries are
    /// collapsed into `Elements` first (taint unioned), then all remaining
    /// values are set to `Unknown`.
    ///
    /// Post-condition: no `Index(*)` keys in `fields`.
    pub fn widen(&mut self) {
        // Collapse all Index entries into Elements per object.
        let objects_with_indices: HashSet<HeapObjectId> = self
            .fields
            .keys()
            .filter(|k| matches!(k.field, FieldSlot::Index(_)))
            .map(|k| k.object)
            .collect();
        for obj in objects_with_indices {
            self.collapse_indices_to_elements(obj);
        }

        // Widen all remaining values to Unknown; preserve taint.
        for value in self.fields.values_mut() {
            *value = SymbolicValue::Unknown;
        }
        // tainted_keys intentionally NOT cleared.
    }

    /// Count non-index fields stored for a specific object.
    ///
    /// Excludes `Index(*)` entries, those are bounded separately by
    /// [`MAX_TRACKED_INDICES`] via [`count_indices_for`].
    fn fields_for_object(&self, object: HeapObjectId) -> usize {
        self.fields
            .keys()
            .filter(|k| k.object == object && !matches!(k.field, FieldSlot::Index(_)))
            .count()
    }

    /// Count distinct `Index(*)` entries for a specific object.
    fn count_indices_for(&self, object: HeapObjectId) -> usize {
        self.fields
            .keys()
            .filter(|k| k.object == object && matches!(k.field, FieldSlot::Index(_)))
            .count()
    }

    /// Collapse all `Index(*)` entries for `object` into `Elements`.
    ///
    /// - Taint is unioned: if any `Index(*)` was tainted, `Elements` becomes
    ///   tainted (preserving any pre-existing `Elements` taint).
    /// - Value is set to `Unknown` (no meaningful union of distinct symbolic
    ///   expressions).
    /// - All `Index(*)` entries are removed.
    fn collapse_indices_to_elements(&mut self, object: HeapObjectId) {
        let index_keys: Vec<HeapKey> = self
            .fields
            .keys()
            .filter(|k| k.object == object && matches!(k.field, FieldSlot::Index(_)))
            .cloned()
            .collect();

        let any_tainted = index_keys.iter().any(|k| self.tainted_keys.contains(k));

        for k in &index_keys {
            self.fields.remove(k);
            self.tainted_keys.remove(k);
        }

        let elem_key = HeapKey {
            object,
            field: FieldSlot::Elements,
        };
        // Union taint: preserve existing Elements taint.
        if any_tainted {
            self.tainted_keys.insert(elem_key.clone());
        }
        // Value → Unknown (may already exist; overwrite is fine).
        self.fields.insert(elem_key, SymbolicValue::Unknown);
    }
}

//  Helpers

/// Resolve a container operation index argument to a [`FieldSlot`].
///
/// When the index SSA value is a provably non-negative integer constant
/// within [`MAX_TRACKED_INDICES`], returns `Index(n)`.  Otherwise returns
/// `Elements` (conservative fallback).
pub fn resolve_index_slot(
    index_val: SsaValue,
    const_values: &HashMap<SsaValue, ConstLattice>,
) -> FieldSlot {
    if let Some(ConstLattice::Int(n)) = const_values.get(&index_val) {
        if *n >= 0 && (*n as u64) < MAX_TRACKED_INDICES as u64 {
            return FieldSlot::Index(*n as u64);
        }
    }
    FieldSlot::Elements
}

/// Parse a dotted define/var_name string into `(receiver, field)`.
///
/// Splits on the last `.`:
/// - `"user.name"` → `Some(("user", "name"))`
/// - `"a.b.c"` → `Some(("a.b", "c"))`
/// - `"noDot"` → `None`
/// - `".field"` → `None` (empty receiver)
/// - `"obj."` → `None` (empty field)
pub fn split_field_access(dotted: &str) -> Option<(&str, &str)> {
    let dot_pos = dotted.rfind('.')?;
    if dot_pos == 0 || dot_pos == dotted.len() - 1 {
        return None;
    }
    Some((&dotted[..dot_pos], &dotted[dot_pos + 1..]))
}

/// Resolve a receiver name to an SSA value by scanning `value_defs` backwards.
///
/// Finds the most recent definition of `receiver_name` that precedes
/// `current_value` (by SSA value index).  Returns `None` if not found.
pub fn resolve_receiver_ssa(
    receiver_name: &str,
    ssa: &SsaBody,
    current_value: SsaValue,
) -> Option<SsaValue> {
    let limit = (current_value.0 as usize).min(ssa.value_defs.len());
    for idx in (0..limit).rev() {
        if let Some(ref name) = ssa.value_defs[idx].var_name {
            if name == receiver_name {
                return Some(SsaValue(idx as u32));
            }
        }
    }
    None
}

/// Resolve an SSA value to a singleton `HeapObjectId` via points-to analysis.
///
/// Returns `Some` only when the points-to set contains exactly one object.
/// May-alias (set size > 1) or unknown (not in result) returns `None` ,
/// the caller should fall through to existing behavior (sound: never pick
/// among ambiguous options).
pub fn resolve_singleton_object(
    ssa_val: SsaValue,
    points_to: &PointsToResult,
) -> Option<HeapObjectId> {
    let pts = points_to.get(ssa_val)?;
    if pts.len() == 1 {
        pts.iter().next().copied()
    } else {
        None
    }
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(n: u32) -> HeapObjectId {
        HeapObjectId(SsaValue(n))
    }

    fn named_key(obj_id: u32, field: &str) -> HeapKey {
        HeapKey {
            object: obj(obj_id),
            field: FieldSlot::Named(field.to_string()),
        }
    }

    fn elements_key(obj_id: u32) -> HeapKey {
        HeapKey {
            object: obj(obj_id),
            field: FieldSlot::Elements,
        }
    }

    #[test]
    fn store_load_roundtrip() {
        let mut heap = SymbolicHeap::new();
        let key = named_key(0, "name");
        let val = SymbolicValue::ConcreteStr("alice".to_string());
        heap.store(key.clone(), val.clone(), false);
        assert_eq!(heap.load(&key), val);
    }

    #[test]
    fn load_missing_returns_unknown() {
        let heap = SymbolicHeap::new();
        let key = named_key(0, "name");
        assert_eq!(heap.load(&key), SymbolicValue::Unknown);
    }

    #[test]
    fn taint_propagation_through_store_load() {
        let mut heap = SymbolicHeap::new();
        let key = named_key(0, "name");
        heap.store(key.clone(), SymbolicValue::Symbol(SsaValue(10)), true);
        assert!(heap.is_tainted(&key));

        // Overwrite with non-tainted value
        heap.store(key.clone(), SymbolicValue::Concrete(42), false);
        assert!(!heap.is_tainted(&key));
    }

    #[test]
    fn max_heap_entries_eviction() {
        let mut heap = SymbolicHeap::new();
        // Fill MAX_HEAP_ENTRIES entries across many objects
        for i in 0..MAX_HEAP_ENTRIES as u32 {
            let key = named_key(i, "f");
            heap.store(key, SymbolicValue::Concrete(i as i64), false);
        }
        assert_eq!(heap.fields.len(), MAX_HEAP_ENTRIES);

        // 65th store should be silently dropped
        let overflow_key = named_key(999, "overflow");
        heap.store(overflow_key.clone(), SymbolicValue::Concrete(999), false);
        assert_eq!(heap.load(&overflow_key), SymbolicValue::Unknown);
        assert_eq!(heap.fields.len(), MAX_HEAP_ENTRIES);
    }

    #[test]
    fn max_fields_per_object_eviction() {
        let mut heap = SymbolicHeap::new();
        // Fill MAX_FIELDS_PER_OBJECT fields on one object
        for i in 0..MAX_FIELDS_PER_OBJECT {
            let key = named_key(0, &format!("field_{i}"));
            heap.store(key, SymbolicValue::Concrete(i as i64), false);
        }
        assert_eq!(heap.fields_for_object(obj(0)), MAX_FIELDS_PER_OBJECT);

        // 9th field on same object should be dropped
        let overflow_key = named_key(0, "overflow");
        heap.store(overflow_key.clone(), SymbolicValue::Concrete(99), false);
        assert_eq!(heap.load(&overflow_key), SymbolicValue::Unknown);
        assert_eq!(heap.fields_for_object(obj(0)), MAX_FIELDS_PER_OBJECT);

        // But a different object is fine
        let other_key = named_key(1, "ok");
        heap.store(other_key.clone(), SymbolicValue::Concrete(1), false);
        assert_eq!(heap.load(&other_key), SymbolicValue::Concrete(1));
    }

    #[test]
    fn widen_preserves_taint_clears_values() {
        let mut heap = SymbolicHeap::new();
        let key = named_key(0, "name");
        heap.store(
            key.clone(),
            SymbolicValue::ConcreteStr("alice".to_string()),
            true,
        );

        heap.widen();

        // Value is Unknown after widening
        assert_eq!(heap.load(&key), SymbolicValue::Unknown);
        // Taint is preserved
        assert!(heap.is_tainted(&key));
    }

    #[test]
    fn split_field_access_cases() {
        assert_eq!(split_field_access("obj.field"), Some(("obj", "field")));
        assert_eq!(split_field_access("a.b.c"), Some(("a.b", "c")));
        assert_eq!(split_field_access("noDot"), None);
        assert_eq!(split_field_access(".field"), None);
        assert_eq!(split_field_access("obj."), None);
        assert_eq!(split_field_access(""), None);
        assert_eq!(split_field_access("."), None);
    }

    #[test]
    fn resolve_singleton_returns_none_for_absent() {
        // PointsToResult::empty() has no entries → None for any query.
        let pts = PointsToResult::empty();
        assert_eq!(resolve_singleton_object(SsaValue(0), &pts), None);
        assert_eq!(resolve_singleton_object(SsaValue(99), &pts), None);
    }

    #[test]
    fn field_slot_named_vs_elements_distinct() {
        let mut heap = SymbolicHeap::new();
        let named = named_key(0, "items");
        let elements = elements_key(0);

        heap.store(named.clone(), SymbolicValue::Concrete(1), false);
        heap.store(elements.clone(), SymbolicValue::Concrete(2), true);

        assert_eq!(heap.load(&named), SymbolicValue::Concrete(1));
        assert_eq!(heap.load(&elements), SymbolicValue::Concrete(2));
        assert!(!heap.is_tainted(&named));
        assert!(heap.is_tainted(&elements));
    }

    #[test]
    fn field_access_recording() {
        let mut heap = SymbolicHeap::new();
        assert!(heap.field_accesses().is_empty());

        heap.record_access(FieldAccessRecord {
            object_name: "user".to_string(),
            field_name: "name".to_string(),
            ssa_value: SsaValue(5),
        });

        assert_eq!(heap.field_accesses().len(), 1);
        assert_eq!(heap.field_accesses()[0].object_name, "user");
        assert_eq!(heap.field_accesses()[0].field_name, "name");
    }

    // ── Index sensitivity tests ────────────────────────────────

    fn index_key(obj_id: u32, idx: u64) -> HeapKey {
        HeapKey {
            object: obj(obj_id),
            field: FieldSlot::Index(idx),
        }
    }

    #[test]
    fn per_index_store_load() {
        let mut heap = SymbolicHeap::new();
        heap.store(index_key(0, 0), SymbolicValue::Concrete(10), false);

        assert_eq!(heap.load(&index_key(0, 0)), SymbolicValue::Concrete(10));
        // Different index: not stored → Unknown
        assert_eq!(heap.load(&index_key(0, 1)), SymbolicValue::Unknown);
        // Elements: not stored → Unknown
        assert_eq!(heap.load(&elements_key(0)), SymbolicValue::Unknown);
    }

    #[test]
    fn index_load_falls_back_to_elements() {
        let mut heap = SymbolicHeap::new();
        heap.store(elements_key(0), SymbolicValue::Concrete(99), false);

        // Index(0) not stored → falls back to Elements value.
        assert_eq!(heap.load(&index_key(0, 0)), SymbolicValue::Concrete(99));
        assert_eq!(heap.load(&index_key(0, 5)), SymbolicValue::Concrete(99));
    }

    #[test]
    fn index_taint_includes_elements_taint() {
        let mut heap = SymbolicHeap::new();
        heap.store(elements_key(0), SymbolicValue::Unknown, true);

        // Elements taint poisons all Index reads.
        assert!(heap.is_tainted(&index_key(0, 0)));
        assert!(heap.is_tainted(&index_key(0, 7)));
        // But not a different object.
        assert!(!heap.is_tainted(&index_key(1, 0)));
    }

    #[test]
    fn index_and_elements_coexist() {
        let mut heap = SymbolicHeap::new();
        heap.store(index_key(0, 0), SymbolicValue::Concrete(10), false);
        heap.store(elements_key(0), SymbolicValue::Concrete(99), true);

        // Value: precise Index(0) wins over Elements.
        assert_eq!(heap.load(&index_key(0, 0)), SymbolicValue::Concrete(10));
        // Value: Index(1) not stored → falls back to Elements.
        assert_eq!(heap.load(&index_key(0, 1)), SymbolicValue::Concrete(99));
        // Taint: Elements taint poisons Index(0) reads.
        assert!(heap.is_tainted(&index_key(0, 0)));
    }

    #[test]
    fn elements_store_after_index_preserves_value() {
        let mut heap = SymbolicHeap::new();
        // Step 1: precise store to Index(1).
        heap.store(
            index_key(0, 1),
            SymbolicValue::ConcreteStr("safe".to_string()),
            false,
        );
        // Step 2: unknown/dynamic store to Elements (tainted).
        heap.store(elements_key(0), SymbolicValue::Unknown, true);

        // Value: Index(1) still wins (precise).
        assert_eq!(
            heap.load(&index_key(0, 1)),
            SymbolicValue::ConcreteStr("safe".to_string())
        );
        // Taint: conservative, Elements taint poisons Index(1).
        assert!(heap.is_tainted(&index_key(0, 1)));
    }

    #[test]
    fn index_overflow_collapses() {
        let mut heap = SymbolicHeap::new();
        // Fill MAX_TRACKED_INDICES indices, mark last one tainted.
        for i in 0..MAX_TRACKED_INDICES as u64 {
            let tainted = i == (MAX_TRACKED_INDICES as u64 - 1);
            heap.store(index_key(0, i), SymbolicValue::Concrete(i as i64), tainted);
        }
        assert_eq!(heap.count_indices_for(obj(0)), MAX_TRACKED_INDICES);

        // One more triggers collapse.
        heap.store(
            index_key(0, MAX_TRACKED_INDICES as u64),
            SymbolicValue::Concrete(999),
            false,
        );

        // No Index(*) keys remain.
        assert_eq!(heap.count_indices_for(obj(0)), 0);
        // Elements exists and carries taint (from the previously tainted index).
        assert!(heap.is_tainted(&elements_key(0)));
        // Elements value is the overflow store's value (collapse wrote Unknown,
        // then the redirect wrote 999).
        assert_eq!(heap.load(&elements_key(0)), SymbolicValue::Concrete(999));
    }

    #[test]
    fn widen_collapses_indices() {
        let mut heap = SymbolicHeap::new();
        heap.store(index_key(0, 0), SymbolicValue::Concrete(10), true);
        heap.store(index_key(0, 1), SymbolicValue::Concrete(20), false);

        heap.widen();

        // No Index keys remain.
        assert_eq!(heap.count_indices_for(obj(0)), 0);
        // Elements value is Unknown (widened).
        assert_eq!(heap.load(&elements_key(0)), SymbolicValue::Unknown);
        // Elements taint preserved (Index(0) was tainted).
        assert!(heap.is_tainted(&elements_key(0)));
    }

    #[test]
    fn fingerprint_distinguishes_indices() {
        let mut h1 = SymbolicHeap::new();
        h1.store(index_key(0, 0), SymbolicValue::Concrete(42), false);

        let mut h2 = SymbolicHeap::new();
        h2.store(index_key(0, 1), SymbolicValue::Concrete(42), false);

        assert_ne!(h1.fingerprint(), h2.fingerprint());
    }

    #[test]
    fn resolve_index_slot_cases() {
        let mut cv = HashMap::new();
        cv.insert(SsaValue(0), ConstLattice::Int(3));
        cv.insert(SsaValue(1), ConstLattice::Int(-1));
        cv.insert(SsaValue(2), ConstLattice::Int(MAX_TRACKED_INDICES as i64));
        cv.insert(SsaValue(3), ConstLattice::Str("hello".into()));

        // Known positive int within bounds → Index(3).
        assert_eq!(resolve_index_slot(SsaValue(0), &cv), FieldSlot::Index(3));
        // Negative → Elements.
        assert_eq!(resolve_index_slot(SsaValue(1), &cv), FieldSlot::Elements);
        // Out of bounds (= MAX_TRACKED_INDICES) → Elements.
        assert_eq!(resolve_index_slot(SsaValue(2), &cv), FieldSlot::Elements);
        // Not an int → Elements.
        assert_eq!(resolve_index_slot(SsaValue(3), &cv), FieldSlot::Elements);
        // Missing from const_values → Elements.
        assert_eq!(resolve_index_slot(SsaValue(99), &cv), FieldSlot::Elements);
    }

    #[test]
    fn field_slot_ordering() {
        let slots = vec![
            FieldSlot::Named("b".to_string()),
            FieldSlot::Index(1),
            FieldSlot::Elements,
            FieldSlot::Named("a".to_string()),
            FieldSlot::Index(0),
        ];
        let mut sorted = slots.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                FieldSlot::Elements,
                FieldSlot::Index(0),
                FieldSlot::Index(1),
                FieldSlot::Named("a".to_string()),
                FieldSlot::Named("b".to_string()),
            ]
        );
    }
}
