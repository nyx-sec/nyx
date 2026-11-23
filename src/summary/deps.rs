//! Read tracking for incremental pass 2.
//!
//! Pass 2 analyses every file against the shared [`GlobalSummaries`]. To reuse
//! a file's pass-2 result on a later scan we have to know every piece of that
//! shared state the analysis looked at. While a trace is active on the current
//! thread, each read accessor of `GlobalSummaries` logs what it looked up and
//! a fingerprint of what it found. A later scan replays the log against the new
//! state: when every lookup still finds the same thing, the analysis (a
//! deterministic function of file bytes, settings and these answers) would
//! produce the same output, so the cached one is used instead.
//!
//! Lookups that found nothing are logged too, so a function added in another
//! file still invalidates a caller whose call used to be unresolved.
//!
//! Per-file analysis runs on one thread (no nested rayon), so a thread-local
//! recorder sees every read of one analysis and nothing else.
//!
//! [`GlobalSummaries`]: super::GlobalSummaries

use crate::symbol::{FuncKey, Lang};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize, ser};
use std::cell::{Cell, RefCell};
use std::marker::PhantomData;

/// Content fingerprint: the first 8 bytes of a BLAKE3 digest.
pub type Fp = u64;

/// Fingerprint recorded when a lookup found nothing.
pub const ABSENT: Fp = 0x5a5a_0000_dead_0001;

/// Exact-key reads of a per-function map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyedRead {
    /// `FuncSummary` by key.
    Func,
    /// `SsaFuncSummary` by key.
    Ssa,
    /// `CalleeSsaBody` by key.
    Body,
    /// `AuthCheckSummary` by key.
    Auth,
    /// Membership in the call-graph caller set.
    Called,
    /// `get_for_interop` fallback scan for a key without `disambig`.
    Interop,
}

const KEYED_KINDS: usize = 6;

impl KeyedRead {
    fn slot(self) -> usize {
        self as usize
    }
}

/// Whole maps whose size or emptiness an analysis can observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MapId {
    Funcs,
    Ssa,
    Bodies,
    Auth,
    RouterFacts,
    CrossPackageImports,
    CallerScope,
}

/// Every other read, keyed by its lookup arguments.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NamedRead {
    /// Keys indexed under a bare name.
    LangName(Lang, String),
    /// Keys indexed under `Container::name`.
    Qualified(Lang, String),
    /// Rust keys indexed under `(module_path, name)`.
    RustModule(String, String),
    /// SSA keys indexed under `(lang, namespace, name)`.
    SsaTriple(Lang, String, String),
    /// Cross-file caller-scope accumulator of a callee leaf.
    CallerScope(Lang, String),
    /// Cross-package import map of a file namespace.
    CrossPackageImports(String),
    /// Direct supertypes of a container.
    Supers(Lang, String),
    /// Direct subtypes of a container.
    Subs(Lang, String),
    /// Result of `resolve_cross_file_router_deps` for a child module.
    RouterDeps(String),
    /// Result of the backwards-analysis body pick for a leaf name.
    BodyByLeaf(Lang, String, usize),
    /// Number of entries in a map.
    MapLen(MapId),
    /// Whether a map has any entries.
    MapNonEmpty(MapId),
    /// SSA summaries of every function with this exact name.
    SsaByName(String),
    /// Whether a path is a regular file.
    IsFile(String),
}

/// The reads one analysis made, with the fingerprint of each answer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DepTrace {
    keyed: Vec<(KeyedRead, FuncKey, Fp)>,
    named: Vec<(NamedRead, Fp)>,
    /// Set when the analysis read shared state in a way the trace cannot
    /// replay (for example iterating a whole map). Such a trace never holds.
    opaque: bool,
}

/// Answers a replayed read against the current shared state.
pub trait DepOracle {
    fn keyed_fp(&self, kind: KeyedRead, key: &FuncKey) -> Fp;
    fn named_fp(&self, read: &NamedRead) -> Fp;
}

impl DepTrace {
    /// Whether replaying every read against `oracle` gives the recorded
    /// answers.  Stops at the first difference.
    pub fn holds(&self, oracle: &impl DepOracle) -> bool {
        if self.opaque {
            return false;
        }
        let _quiet = Suppress::new();
        self.keyed
            .iter()
            .all(|(kind, key, fp)| oracle.keyed_fp(*kind, key) == *fp)
            && self
                .named
                .iter()
                .all(|(read, fp)| replay_named(oracle, read) == *fp)
    }

    pub fn is_opaque(&self) -> bool {
        self.opaque
    }

    pub fn len(&self) -> usize {
        self.keyed.len() + self.named.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Union of two traces.  When both recorded the same read the first
    /// answer is kept: in a fixed-point loop that is the answer seen before
    /// the loop's own writes, which is the state a later replay compares
    /// against.
    pub fn merge(&mut self, other: DepTrace) {
        self.opaque |= other.opaque;
        let mut seen_keyed: FxHashSet<(KeyedRead, FuncKey)> = self
            .keyed
            .iter()
            .map(|(k, key, _)| (*k, key.clone()))
            .collect();
        for (kind, key, fp) in other.keyed {
            if seen_keyed.insert((kind, key.clone())) {
                self.keyed.push((kind, key, fp));
            }
        }
        let mut seen_named: FxHashSet<NamedRead> =
            self.named.iter().map(|(r, _)| r.clone()).collect();
        for (read, fp) in other.named {
            if seen_named.insert(read.clone()) {
                self.named.push((read, fp));
            }
        }
    }

    /// Drop value reads of keys the traced unit wrote itself.
    ///
    /// A fixed-point batch reads its own summaries at every iteration, so
    /// those answers change while it runs.  They are a function of the
    /// batch's files (unchanged when the cache is consulted) and of the
    /// batch's other reads, so they carry no extra dependency.
    pub fn retain_external(&mut self, written: &FxHashSet<FuncKey>) {
        self.keyed.retain(|(kind, key, _)| {
            !matches!(
                kind,
                KeyedRead::Func | KeyedRead::Ssa | KeyedRead::Body | KeyedRead::Auth
            ) || !written.contains(key)
        });
    }
}

fn replay_named(oracle: &impl DepOracle, read: &NamedRead) -> Fp {
    match read {
        NamedRead::IsFile(path) => fp_bool(std::path::Path::new(path).is_file()),
        other => oracle.named_fp(other),
    }
}

// ── Thread-local recorder ───────────────────────────────────────────────

#[derive(Default)]
struct Recorder {
    keyed: [FxHashMap<FuncKey, Fp>; KEYED_KINDS],
    named: FxHashMap<NamedRead, Fp>,
    opaque: bool,
}

impl Recorder {
    fn into_trace(self) -> DepTrace {
        let mut keyed = Vec::new();
        for (slot, map) in self.keyed.into_iter().enumerate() {
            let kind = KEYED_FROM_SLOT[slot];
            keyed.extend(map.into_iter().map(|(k, fp)| (kind, k, fp)));
        }
        DepTrace {
            keyed,
            named: self.named.into_iter().collect(),
            opaque: self.opaque,
        }
    }
}

const KEYED_FROM_SLOT: [KeyedRead; KEYED_KINDS] = [
    KeyedRead::Func,
    KeyedRead::Ssa,
    KeyedRead::Body,
    KeyedRead::Auth,
    KeyedRead::Called,
    KeyedRead::Interop,
];

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static QUIET: Cell<u32> = const { Cell::new(0) };
    static RECORDER: RefCell<Recorder> = RefCell::new(Recorder::default());
}

/// Whether reads on this thread are being recorded right now.
#[inline]
pub fn recording() -> bool {
    ACTIVE.with(Cell::get) && QUIET.with(Cell::get) == 0
}

/// Stops recording on this thread while alive.  Used while computing a
/// fingerprint (which may call other accessors) and while replaying.
pub struct Suppress(PhantomData<*const ()>);

impl Suppress {
    pub fn new() -> Self {
        QUIET.with(|q| q.set(q.get() + 1));
        Suppress(PhantomData)
    }
}

impl Default for Suppress {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Suppress {
    fn drop(&mut self) {
        QUIET.with(|q| q.set(q.get() - 1));
    }
}

/// An active trace on the current thread.  Ends when finished or dropped.
pub struct TraceGuard(PhantomData<*const ()>);

/// Start recording reads on the current thread.
pub fn start_trace() -> TraceGuard {
    let was_active = ACTIVE.with(|a| a.replace(true));
    debug_assert!(!was_active, "nested dependency trace");
    RECORDER.with(|r| *r.borrow_mut() = Recorder::default());
    TraceGuard(PhantomData)
}

impl TraceGuard {
    /// Stop recording and return what was read.
    pub fn finish(self) -> DepTrace {
        let rec = RECORDER.with(|r| std::mem::take(&mut *r.borrow_mut()));
        // Drop deactivates.
        drop(self);
        rec.into_trace()
    }
}

impl Drop for TraceGuard {
    fn drop(&mut self) {
        ACTIVE.with(|a| a.set(false));
        RECORDER.with(|r| *r.borrow_mut() = Recorder::default());
    }
}

/// Record an exact-key read.  `fp` runs only for the first read of `key`.
#[inline]
pub fn note_keyed(kind: KeyedRead, key: &FuncKey, fp: impl FnOnce() -> Fp) {
    if !recording() {
        return;
    }
    let seen = RECORDER.with(|r| r.borrow().keyed[kind.slot()].contains_key(key));
    if seen {
        return;
    }
    let value = {
        let _quiet = Suppress::new();
        fp()
    };
    RECORDER.with(|r| {
        r.borrow_mut().keyed[kind.slot()].insert(key.clone(), value);
    });
}

/// Record a read described by `read`.  Both closures run only while
/// recording, and `fp` only for the first time this read is seen.
#[inline]
pub fn note_named(read: impl FnOnce() -> NamedRead, fp: impl FnOnce() -> Fp) {
    if !recording() {
        return;
    }
    let read = read();
    let seen = RECORDER.with(|r| r.borrow().named.contains_key(&read));
    if seen {
        return;
    }
    let value = {
        let _quiet = Suppress::new();
        fp()
    };
    RECORDER.with(|r| {
        r.borrow_mut().named.insert(read, value);
    });
}

/// Record that the analysis read shared state the trace cannot replay.
#[inline]
pub fn note_opaque() {
    if recording() {
        RECORDER.with(|r| r.borrow_mut().opaque = true);
    }
}

/// Record a filesystem `is_file` probe made during analysis.
pub fn note_is_file(path: &std::path::Path, is_file: bool) {
    note_named(
        || NamedRead::IsFile(path.to_string_lossy().into_owned()),
        || fp_bool(is_file),
    );
}

// ── Fingerprints ────────────────────────────────────────────────────────

pub fn fp_bool(b: bool) -> Fp {
    if b {
        0x0000_7472_7565
    } else {
        0x0066_616c_7365
    }
}

fn finish(h: &blake3::Hasher) -> Fp {
    let out = h.finalize();
    let b = out.as_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Canonical fingerprint of a serializable value.
///
/// Maps are hashed as a multiset of entries, so two maps with the same
/// entries agree whatever their iteration order (std `HashMap` order changes
/// from one process to the next).  Sequences keep their order.
pub fn fp_value<T: Serialize + ?Sized>(value: &T) -> Fp {
    let mut w = FpWriter::new();
    match value.serialize(&mut w) {
        Ok(()) => finish(&w.h),
        // Serialization of in-memory analysis types does not fail; if it
        // ever does, give a value no other content can produce so the read
        // never matches.
        Err(_) => !ABSENT,
    }
}

/// Fingerprint of an optional value via [`fp_value`].
pub fn fp_opt<T: Serialize>(value: Option<&T>) -> Fp {
    value.map_or(ABSENT, fp_value)
}

/// Fingerprint of a `Debug` rendering, for small types without `Serialize`
/// whose rendering is deterministic (no hash-ordered fields).
pub fn fp_debug<T: std::fmt::Debug + ?Sized>(value: &T) -> Fp {
    let mut h = blake3::Hasher::new();
    h.update(format!("{value:?}").as_bytes());
    finish(&h)
}

/// Fingerprint of a key list, order included.
pub fn fp_keys<'a>(keys: impl IntoIterator<Item = &'a FuncKey>) -> Fp {
    let mut w = FpWriter::new();
    let mut n: u64 = 0;
    for k in keys {
        // FuncKey serialization only builds owned strings; it cannot fail.
        let _ = k.serialize(&mut w);
        n += 1;
    }
    w.h.update(&n.to_le_bytes());
    finish(&w.h)
}

/// Fingerprint of a list of strings, order included.
pub fn fp_strs<S: AsRef<str>>(items: &[S]) -> Fp {
    let mut h = blake3::Hasher::new();
    for s in items {
        let s = s.as_ref();
        h.update(&(s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    }
    h.update(&(items.len() as u64).to_le_bytes());
    finish(&h)
}

pub fn fp_usize(n: usize) -> Fp {
    let mut h = blake3::Hasher::new();
    h.update(b"len");
    h.update(&(n as u64).to_le_bytes());
    finish(&h)
}

/// Serializer that feeds a BLAKE3 hasher instead of producing bytes.
struct FpWriter {
    h: blake3::Hasher,
}

impl FpWriter {
    fn new() -> Self {
        FpWriter {
            h: blake3::Hasher::new(),
        }
    }

    fn tag(&mut self, t: u8) {
        self.h.update(&[t]);
    }

    fn raw(&mut self, b: &[u8]) {
        self.h.update(&(b.len() as u64).to_le_bytes());
        self.h.update(b);
    }
}

#[derive(Debug)]
pub struct FpError(String);

impl std::fmt::Display for FpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FpError {}

impl ser::Error for FpError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        FpError(msg.to_string())
    }
}

macro_rules! fp_num {
    ($name:ident, $ty:ty, $tag:expr) => {
        fn $name(self, v: $ty) -> Result<(), FpError> {
            self.tag($tag);
            self.h.update(&v.to_le_bytes());
            Ok(())
        }
    };
}

impl<'a> ser::Serializer for &'a mut FpWriter {
    type Ok = ();
    type Error = FpError;
    type SerializeSeq = FpSeq<'a>;
    type SerializeTuple = FpSeq<'a>;
    type SerializeTupleStruct = FpSeq<'a>;
    type SerializeTupleVariant = FpSeq<'a>;
    type SerializeMap = FpMap<'a>;
    type SerializeStruct = FpSeq<'a>;
    type SerializeStructVariant = FpSeq<'a>;

    fn serialize_bool(self, v: bool) -> Result<(), FpError> {
        self.tag(1);
        self.h.update(&[v as u8]);
        Ok(())
    }
    fp_num!(serialize_i8, i8, 2);
    fp_num!(serialize_i16, i16, 3);
    fp_num!(serialize_i32, i32, 4);
    fp_num!(serialize_i64, i64, 5);
    fp_num!(serialize_i128, i128, 6);
    fp_num!(serialize_u8, u8, 7);
    fp_num!(serialize_u16, u16, 8);
    fp_num!(serialize_u32, u32, 9);
    fp_num!(serialize_u64, u64, 10);
    fp_num!(serialize_u128, u128, 11);

    fn serialize_f32(self, v: f32) -> Result<(), FpError> {
        self.tag(12);
        self.h.update(&v.to_bits().to_le_bytes());
        Ok(())
    }
    fn serialize_f64(self, v: f64) -> Result<(), FpError> {
        self.tag(13);
        self.h.update(&v.to_bits().to_le_bytes());
        Ok(())
    }
    fn serialize_char(self, v: char) -> Result<(), FpError> {
        self.tag(14);
        self.h.update(&(v as u32).to_le_bytes());
        Ok(())
    }
    fn serialize_str(self, v: &str) -> Result<(), FpError> {
        self.tag(15);
        self.raw(v.as_bytes());
        Ok(())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), FpError> {
        self.tag(16);
        self.raw(v);
        Ok(())
    }
    fn serialize_none(self) -> Result<(), FpError> {
        self.tag(17);
        Ok(())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<(), FpError> {
        self.tag(18);
        v.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), FpError> {
        self.tag(19);
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), FpError> {
        self.tag(20);
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
    ) -> Result<(), FpError> {
        self.tag(21);
        self.h.update(&idx.to_le_bytes());
        Ok(())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        v: &T,
    ) -> Result<(), FpError> {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        v: &T,
    ) -> Result<(), FpError> {
        self.tag(22);
        self.h.update(&idx.to_le_bytes());
        v.serialize(self)
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<FpSeq<'a>, FpError> {
        self.tag(23);
        Ok(FpSeq { w: self, n: 0 })
    }
    fn serialize_tuple(self, _len: usize) -> Result<FpSeq<'a>, FpError> {
        self.tag(24);
        Ok(FpSeq { w: self, n: 0 })
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<FpSeq<'a>, FpError> {
        self.tag(25);
        Ok(FpSeq { w: self, n: 0 })
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<FpSeq<'a>, FpError> {
        self.tag(26);
        self.h.update(&idx.to_le_bytes());
        Ok(FpSeq { w: self, n: 0 })
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<FpMap<'a>, FpError> {
        Ok(FpMap {
            w: self,
            sum: 0,
            n: 0,
            key: None,
        })
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<FpSeq<'a>, FpError> {
        self.tag(27);
        Ok(FpSeq { w: self, n: 0 })
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<FpSeq<'a>, FpError> {
        self.tag(28);
        self.h.update(&idx.to_le_bytes());
        Ok(FpSeq { w: self, n: 0 })
    }
}

/// Ordered compound: sequences, tuples and struct fields.
pub struct FpSeq<'a> {
    w: &'a mut FpWriter,
    n: u64,
}

impl FpSeq<'_> {
    fn element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), FpError> {
        self.n += 1;
        v.serialize(&mut *self.w)
    }

    fn end_inner(self) -> Result<(), FpError> {
        self.w.tag(29);
        self.w.h.update(&self.n.to_le_bytes());
        Ok(())
    }
}

impl ser::SerializeSeq for FpSeq<'_> {
    type Ok = ();
    type Error = FpError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), FpError> {
        self.element(v)
    }
    fn end(self) -> Result<(), FpError> {
        self.end_inner()
    }
}

impl ser::SerializeTuple for FpSeq<'_> {
    type Ok = ();
    type Error = FpError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), FpError> {
        self.element(v)
    }
    fn end(self) -> Result<(), FpError> {
        self.end_inner()
    }
}

impl ser::SerializeTupleStruct for FpSeq<'_> {
    type Ok = ();
    type Error = FpError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), FpError> {
        self.element(v)
    }
    fn end(self) -> Result<(), FpError> {
        self.end_inner()
    }
}

impl ser::SerializeTupleVariant for FpSeq<'_> {
    type Ok = ();
    type Error = FpError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), FpError> {
        self.element(v)
    }
    fn end(self) -> Result<(), FpError> {
        self.end_inner()
    }
}

impl ser::SerializeStruct for FpSeq<'_> {
    type Ok = ();
    type Error = FpError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        v: &T,
    ) -> Result<(), FpError> {
        // Field names keep `skip_serializing_if` gaps unambiguous.
        self.w.raw(key.as_bytes());
        self.element(v)
    }
    fn end(self) -> Result<(), FpError> {
        self.end_inner()
    }
}

impl ser::SerializeStructVariant for FpSeq<'_> {
    type Ok = ();
    type Error = FpError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        v: &T,
    ) -> Result<(), FpError> {
        self.w.raw(key.as_bytes());
        self.element(v)
    }
    fn end(self) -> Result<(), FpError> {
        self.end_inner()
    }
}

/// Unordered compound: each entry is hashed on its own and the entry
/// hashes are summed, so iteration order does not matter.
pub struct FpMap<'a> {
    w: &'a mut FpWriter,
    sum: u64,
    n: u64,
    key: Option<Fp>,
}

impl ser::SerializeMap for FpMap<'_> {
    type Ok = ();
    type Error = FpError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> Result<(), FpError> {
        let mut sub = FpWriter::new();
        k.serialize(&mut sub)?;
        self.key = Some(finish(&sub.h));
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), FpError> {
        let mut sub = FpWriter::new();
        let k = self.key.take().unwrap_or(ABSENT);
        sub.h.update(&k.to_le_bytes());
        v.serialize(&mut sub)?;
        self.sum = self.sum.wrapping_add(finish(&sub.h));
        self.n += 1;
        Ok(())
    }
    fn end(self) -> Result<(), FpError> {
        self.w.tag(30);
        self.w.h.update(&self.sum.to_le_bytes());
        self.w.h.update(&self.n.to_le_bytes());
        Ok(())
    }
}

/// `serialize_with` helper that writes a hash set in sorted order, so the
/// encoding (and any fingerprint of it) does not depend on how the set was
/// built.
pub fn sorted_set<S, T, H>(set: &std::collections::HashSet<T, H>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Serialize + Ord,
{
    let mut items: Vec<&T> = set.iter().collect();
    items.sort();
    ser::Serializer::collect_seq(s, items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn map_fingerprint_ignores_iteration_order() {
        let mut a: HashMap<String, Vec<u32>> = HashMap::new();
        let mut b: HashMap<String, Vec<u32>> = HashMap::with_capacity(64);
        for i in 0..50u32 {
            a.insert(format!("k{i}"), vec![i, i + 1]);
        }
        for i in (0..50u32).rev() {
            b.insert(format!("k{i}"), vec![i, i + 1]);
        }
        assert_eq!(fp_value(&a), fp_value(&b));
        let sorted: BTreeMap<_, _> = a.clone().into_iter().collect();
        assert_eq!(fp_value(&a), fp_value(&sorted));
        b.insert("k0".into(), vec![9]);
        assert_ne!(fp_value(&a), fp_value(&b));
    }

    #[test]
    fn sequence_fingerprint_keeps_order() {
        assert_ne!(fp_value(&vec![1u32, 2]), fp_value(&vec![2u32, 1]));
        assert_ne!(
            fp_value(&vec![vec![1u32], vec![]]),
            fp_value(&vec![vec![], vec![1u32]])
        );
    }

    #[test]
    fn struct_fields_with_gaps_do_not_collide() {
        #[derive(Serialize)]
        struct S {
            #[serde(skip_serializing_if = "Option::is_none")]
            a: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            b: Option<u32>,
        }
        let x = S {
            a: Some(1),
            b: None,
        };
        let y = S {
            a: None,
            b: Some(1),
        };
        assert_ne!(fp_value(&x), fp_value(&y));
    }

    #[test]
    fn recorder_dedupes_and_suppresses() {
        let key = FuncKey::default();
        let guard = start_trace();
        let mut calls = 0;
        note_keyed(KeyedRead::Func, &key, || {
            calls += 1;
            7
        });
        note_keyed(KeyedRead::Func, &key, || {
            calls += 1;
            8
        });
        {
            let _q = Suppress::new();
            note_named(|| NamedRead::MapLen(MapId::Bodies), || 1);
        }
        note_named(|| NamedRead::LangName(Lang::Rust, "f".into()), || 3);
        let trace = guard.finish();
        assert_eq!(calls, 1);
        assert_eq!(trace.keyed.len(), 1);
        assert_eq!(trace.keyed[0].2, 7);
        assert_eq!(trace.named.len(), 1);
        assert!(!recording());
    }

    struct Fixed;
    impl DepOracle for Fixed {
        fn keyed_fp(&self, _: KeyedRead, _: &FuncKey) -> Fp {
            7
        }
        fn named_fp(&self, _: &NamedRead) -> Fp {
            3
        }
    }

    #[test]
    fn trace_holds_only_when_every_answer_matches() {
        let guard = start_trace();
        note_keyed(KeyedRead::Ssa, &FuncKey::default(), || 7);
        note_named(|| NamedRead::Qualified(Lang::Go, "T::m".into()), || 3);
        let trace = guard.finish();
        assert!(trace.holds(&Fixed));

        let guard = start_trace();
        note_named(|| NamedRead::Qualified(Lang::Go, "T::m".into()), || 4);
        assert!(!guard.finish().holds(&Fixed));

        let guard = start_trace();
        note_opaque();
        assert!(!guard.finish().holds(&Fixed));
    }

    #[test]
    fn retain_external_drops_only_written_value_reads() {
        let k = FuncKey::default();
        let guard = start_trace();
        note_keyed(KeyedRead::Ssa, &k, || 1);
        note_keyed(KeyedRead::Called, &k, || 2);
        let mut trace = guard.finish();
        let written: FxHashSet<FuncKey> = [k].into_iter().collect();
        trace.retain_external(&written);
        assert_eq!(trace.keyed.len(), 1);
        assert_eq!(trace.keyed[0].0, KeyedRead::Called);
    }
}
