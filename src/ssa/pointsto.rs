//! Container operation classification for taint propagation.
//!
//! Recognises common container store/load patterns (push, pop, get, set, etc.)
//! across all supported languages so that taint flows correctly through
//! collection operations.

use crate::labels::bare_method_name;
use crate::symbol::Lang;
use smallvec::SmallVec;

// ── Container operation model ───────────────────────────────────────────

/// Describes how a container method moves taint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerOp {
    /// Taint flows from the listed argument positions into the receiver
    /// container (e.g. `arr.push(val)`, val taint merges into arr).
    ///
    /// `index_arg`: when `Some(pos)`, the argument at that logical position
    /// is the container index/key.  If constant-propagation proves it a
    /// non-negative integer, the taint engine stores into `HeapSlot::Index(n)`
    /// instead of `HeapSlot::Elements`.  `None` → always `Elements`.
    Store {
        value_args: SmallVec<[usize; 2]>,
        index_arg: Option<usize>,
    },
    /// Taint flows from the receiver container to the call's return value
    /// (e.g. `arr.pop()`, `items.join('')`).
    ///
    /// `index_arg`: same semantics as `Store::index_arg`, when present and
    /// provably constant, loads from `HeapSlot::Index(n)`.
    Load { index_arg: Option<usize> },
    /// Taint flows from the receiver container into the argument at
    /// `dest_arg`, i.e. the "writeback" pattern where a method writes its
    /// decoded/loaded value into a caller-supplied destination rather than
    /// returning it. Used for the Go `*.Decode(&dest)` family
    /// (`json.Decoder.Decode`, `xml.Decoder.Decode`, `gob.Decoder.Decode`),
    /// where `r.Body → json.NewDecoder(r.Body).Decode(&dest)` should taint
    /// `dest` even though `Decode` returns only an `error`.
    Writeback { dest_arg: usize },
}

/// Convenience: store with a single value argument, no index tracking.
#[inline]
fn store(pos: usize) -> Option<ContainerOp> {
    let mut v = SmallVec::new();
    v.push(pos);
    Some(ContainerOp::Store {
        value_args: v,
        index_arg: None,
    })
}

/// Convenience: store with index tracking.  `val_pos` is the value arg,
/// `idx_pos` is the index/key arg (resolved via const propagation).
#[inline]
fn store_indexed(val_pos: usize, idx_pos: usize) -> Option<ContainerOp> {
    let mut v = SmallVec::new();
    v.push(val_pos);
    Some(ContainerOp::Store {
        value_args: v,
        index_arg: Some(idx_pos),
    })
}

/// Convenience: store with two value arguments, no index tracking.
#[inline]
fn store2(a: usize, b: usize) -> Option<ContainerOp> {
    let mut v = SmallVec::new();
    v.push(a);
    v.push(b);
    Some(ContainerOp::Store {
        value_args: v,
        index_arg: None,
    })
}

/// Convenience: load without index tracking.
#[inline]
fn load() -> Option<ContainerOp> {
    Some(ContainerOp::Load { index_arg: None })
}

/// Convenience: load with index tracking.  `idx_pos` is the index/key arg.
#[inline]
fn load_indexed(idx_pos: usize) -> Option<ContainerOp> {
    Some(ContainerOp::Load {
        index_arg: Some(idx_pos),
    })
}

// ── Classification ──────────────────────────────────────────────────────

/// Classify a callee as a container operation for the given language.
///
/// `callee` is the raw callee string from `NodeInfo.callee` (e.g.
/// `"items.push"`, `"arr.pop"`). We extract the last segment after `.`
/// for method matching. For Go builtins (e.g. `"append"`), the full name
/// is used.
///
/// Returns `None` if the callee is not a recognised container operation.
pub fn classify_container_op(callee: &str, lang: Lang) -> Option<ContainerOp> {
    // Extract method name: last segment after '.' (or full name if no dot).
    let method = bare_method_name(callee);

    match lang {
        Lang::JavaScript | Lang::TypeScript => classify_js(method),
        Lang::Python => classify_python(method),
        Lang::Java => classify_java(method),
        Lang::Go => classify_go(method, callee),
        Lang::Ruby => classify_ruby(method),
        Lang::Php => classify_php(method),
        Lang::C | Lang::Cpp => classify_cpp(method),
        Lang::Rust => classify_rust(method),
    }
}

// ── Per-language classifiers ────────────────────────────────────────────

fn classify_js(method: &str) -> Option<ContainerOp> {
    match method {
        // Array store
        "push" | "unshift" => store(0),
        // Map/Set store: map.set(key, value), key at 0, value at 1
        "set" => store_indexed(1, 0),
        "add" => store(0), // set.add(value)
        // Array/Map load
        "pop" | "shift" => load(),
        "join" | "flat" | "concat" | "slice" | "toString" => load(),
        // map.get(key), key at 0
        "get" => load_indexed(0),
        "values" | "keys" | "entries" => load(),
        //synthetic callees emitted by CFG
        // lowering for subscript reads/writes (`arr[i]`, `arr[i] = v`).
        "__index_get__" => load_indexed(0),
        "__index_set__" => store_indexed(1, 0),
        _ => None,
    }
}

fn classify_python(method: &str) -> Option<ContainerOp> {
    match method {
        // List store
        "append" | "extend" => store(0),
        "insert" => store_indexed(1, 0), // list.insert(index, value), index at 0, value at 1
        // Set store
        "add" => store(0),
        // Dict store
        "update" => store(0),
        "setdefault" => store2(0, 1), // dict.setdefault(key, default)
        // List/Dict load
        "pop" => load(),
        "get" => load_indexed(0), // dict.get(key) / list index, key/index at 0
        "items" | "values" | "keys" => load(),
        "join" => load(),
        //synthetic callees emitted by CFG
        // lowering for subscript reads/writes (`arr[i]`, `arr[i] = v`).
        "__index_get__" => load_indexed(0),
        "__index_set__" => store_indexed(1, 0),
        _ => None,
    }
}

fn classify_java(method: &str) -> Option<ContainerOp> {
    match method {
        // Collection store
        "add" | "addAll" | "putAll" | "offer" | "push" => store(0),
        // ArrayList.set(index, value), index at 0, value at 1
        "set" => store_indexed(1, 0),
        // Map.put(key, value), key at 0, value at 1
        "put" => store_indexed(1, 0),
        // Collection load: ArrayList.get(index), index at 0
        "get" => load_indexed(0),
        "poll" | "peek" | "remove" | "pop" => load(),
        "stream" | "toArray" | "iterator" => load(),
        _ => None,
    }
}

fn classify_go(method: &str, callee: &str) -> Option<ContainerOp> {
    // Go `append` is a builtin: `result = append(slice, val1, val2, ...)`
    // The callee is just "append" (no receiver dot-path).
    if callee == "append" || method == "append" {
        // arg 0 = existing slice, args 1+ = values to append.
        // Handled specially in try_container_propagation (Go append mode).
        return store(1);
    }
    // Map/slice operations in Go are via index expressions, not method calls,
    // so there are fewer method-based patterns.
    match method {
        "Add" | "Set" | "Store" | "Put" => store(0),
        "Get" | "Load" | "Pop" => load(),
        // Stream-decoder writeback.  In Go, the canonical decode pattern
        // takes a destination as the sole positional argument and returns
        // only an `error`:
        //   decoder := json.NewDecoder(r.Body)
        //   decoder.Decode(&dest)
        // The decoder's receiver chain carries the source taint
        // (`r.Body` → `json.NewDecoder(r.Body)` → `decoder`); without a
        // writeback rule, the destination stays clean and downstream sinks
        // miss the flow. `Unmarshal` is the matching sibling pattern on
        // top-level decoders (e.g. `proto.Unmarshal(buf, &msg)`); the
        // method-call form has the bytes carried via the receiver, not arg 0,
        // so it lines up with the writeback contract just like `Decode`.
        "Decode" | "Unmarshal" => Some(ContainerOp::Writeback { dest_arg: 0 }),
        //synthetic callees emitted by CFG
        // lowering for Go index_expression reads/writes (`arr[i]`,
        // `m[k] = v`).
        "__index_get__" => load_indexed(0),
        "__index_set__" => store_indexed(1, 0),
        _ => None,
    }
}

fn classify_ruby(method: &str) -> Option<ContainerOp> {
    match method {
        "push" | "append" | "unshift" | "store" | "<<" => store(0),
        "pop" | "shift" | "first" | "last" | "fetch" | "join" => load(),
        _ => None,
    }
}

fn classify_php(method: &str) -> Option<ContainerOp> {
    match method {
        "array_push" => store(1), // array_push(&$arr, $val), arr is arg 0, val is arg 1
        "array_pop" | "array_shift" | "current" | "next" | "reset" => load(),
        _ => None,
    }
}

fn classify_cpp(method: &str) -> Option<ContainerOp> {
    match method {
        // Mutating container operations.
        // `assign` overwrites the container's contents with the argument
        // sequence, modeled as Store so the receiver inherits the argument
        // taint, matching the runtime "the values now live inside this
        // container" semantics shared with `push_back`/`emplace_back`.
        "push_back" | "emplace_back" | "insert" | "emplace" | "push" | "assign" => store(0),
        // Map/unordered_map insertion: `m.insert_or_assign(k, v)`, value at 1.
        "insert_or_assign" => store_indexed(1, 0),
        // Read-only container observers.  `find`/`count` return iterators or
        // counts that carry the container's value taint when queried with a
        // tainted needle; `data` returns a pointer to the underlying buffer
        // (its real identity-passthrough behaviour for `c_str`/`data` is
        // refined in the labels phase, but Load propagation gives us the
        // baseline cap-flow without further plumbing).
        "front" | "back" | "pop_back" | "pop_front" | "top" | "find" | "count" | "data" => load(),
        // Indexed reads: `vector::at(i)`, `unordered_map::at(k)`.
        "at" => load_indexed(0),
        // Synthetic callees emitted by CFG lowering for subscript
        // reads/writes. C arrays and C++ raw arrays use the same
        // `subscript_expression` shape as JS/TS, so route them through
        // the same indexed container abstraction.
        "__index_get__" => load_indexed(0),
        "__index_set__" => store_indexed(1, 0),
        _ => None,
    }
}

fn classify_rust(method: &str) -> Option<ContainerOp> {
    match method {
        "push" | "insert" | "extend" => store(0),
        "pop" | "first" | "last" | "iter" | "remove" => load(),
        // vec.get(index), index at 0
        "get" => load_indexed(0),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_push_is_store() {
        let op = classify_container_op("items.push", Lang::JavaScript);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn js_pop_is_load() {
        let op = classify_container_op("arr.pop", Lang::JavaScript);
        assert!(matches!(op, Some(ContainerOp::Load { .. })));
    }

    #[test]
    fn js_join_is_load() {
        let op = classify_container_op("items.join", Lang::JavaScript);
        assert!(matches!(op, Some(ContainerOp::Load { .. })));
    }

    #[test]
    fn python_append_is_store() {
        let op = classify_container_op("commands.append", Lang::Python);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn java_add_is_store() {
        let op = classify_container_op("list.add", Lang::Java);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn go_append_is_store() {
        let op = classify_container_op("append", Lang::Go);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    // CVE Hunt Session 2 (Owncast CVE-2023-3188 / CVE-2024-31450 family):
    // Go `*.Decode(&dest)` is the canonical streaming-decoder writeback ,
    // `json.NewDecoder(r.Body).Decode(&dest)`, `xml.NewDecoder(r).Decode(&out)`,
    // `gob.NewDecoder(buf).Decode(&v)`. The decoder receiver carries the
    // source taint and the destination is arg 0; the writeback rule is the
    // only way taint reaches `dest` because `Decode` itself returns only
    // `error`. The same-shape `Unmarshal` pattern (`proto.Unmarshal`,
    // `tar.Header.Unmarshal`) on a typed receiver follows the same contract.
    #[test]
    fn go_decode_is_writeback_dest_arg_zero() {
        match classify_container_op("decoder.Decode", Lang::Go) {
            Some(ContainerOp::Writeback { dest_arg }) => assert_eq!(dest_arg, 0),
            other => panic!("expected Writeback {{ dest_arg: 0 }}, got {other:?}"),
        }
    }

    #[test]
    fn go_unmarshal_is_writeback_dest_arg_zero() {
        match classify_container_op("hdr.Unmarshal", Lang::Go) {
            Some(ContainerOp::Writeback { dest_arg }) => assert_eq!(dest_arg, 0),
            other => panic!("expected Writeback {{ dest_arg: 0 }}, got {other:?}"),
        }
    }

    #[test]
    fn js_decode_is_not_writeback() {
        // The Writeback rule is a Go-specific pattern; JS/TS `decode`
        // helpers (`Buffer.from(s, 'base64').toString()` etc.) return their
        // result and don't have a writeback contract.  Make sure we didn't
        // accidentally widen the rule into other languages.
        assert!(classify_container_op("decoder.Decode", Lang::JavaScript).is_none());
        assert!(classify_container_op("decoder.Decode", Lang::Python).is_none());
    }

    #[test]
    fn unknown_method_is_none() {
        assert!(classify_container_op("obj.frobnicate", Lang::JavaScript).is_none());
    }

    #[test]
    fn rust_push_is_store() {
        let op = classify_container_op("vec.push", Lang::Rust);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn store_value_args_correct() {
        // JS set → value at arg 1, index at arg 0
        if let Some(ContainerOp::Store {
            value_args,
            index_arg,
        }) = classify_container_op("map.set", Lang::JavaScript)
        {
            assert_eq!(value_args.as_slice(), &[1]);
            assert_eq!(index_arg, Some(0));
        } else {
            panic!("expected Store");
        }
        // JS push → value at arg 0, no index
        if let Some(ContainerOp::Store {
            value_args,
            index_arg,
        }) = classify_container_op("arr.push", Lang::JavaScript)
        {
            assert_eq!(value_args.as_slice(), &[0]);
            assert_eq!(index_arg, None);
        } else {
            panic!("expected Store");
        }
    }

    #[test]
    fn load_index_arg_correct() {
        // JS get → index at arg 0
        if let Some(ContainerOp::Load { index_arg }) =
            classify_container_op("map.get", Lang::JavaScript)
        {
            assert_eq!(index_arg, Some(0));
        } else {
            panic!("expected Load");
        }
        // JS pop → no index
        if let Some(ContainerOp::Load { index_arg }) =
            classify_container_op("arr.pop", Lang::JavaScript)
        {
            assert_eq!(index_arg, None);
        } else {
            panic!("expected Load");
        }
    }

    // ── C++ extras ──────────────────────────────────────

    #[test]
    fn cpp_push_back_is_store() {
        let op = classify_container_op("v.push_back", Lang::Cpp);
        match op {
            Some(ContainerOp::Store {
                value_args,
                index_arg,
            }) => {
                assert_eq!(value_args.as_slice(), &[0]);
                assert_eq!(index_arg, None);
            }
            _ => panic!("expected Store"),
        }
    }

    #[test]
    fn cpp_assign_is_store() {
        // vector::assign(args) overwrites the container's contents, the
        // receiver inherits argument taint just like push_back.
        let op = classify_container_op("v.assign", Lang::Cpp);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn cpp_insert_or_assign_indexes_value() {
        // map::insert_or_assign(key, value), value is at arg 1, key at arg 0.
        match classify_container_op("m.insert_or_assign", Lang::Cpp) {
            Some(ContainerOp::Store {
                value_args,
                index_arg,
            }) => {
                assert_eq!(value_args.as_slice(), &[1]);
                assert_eq!(index_arg, Some(0));
            }
            other => panic!("expected indexed Store, got {other:?}"),
        }
    }

    #[test]
    fn cpp_find_count_data_are_load() {
        for callee in ["m.find", "m.count", "v.data"] {
            assert!(
                matches!(
                    classify_container_op(callee, Lang::Cpp),
                    Some(ContainerOp::Load { .. })
                ),
                "{callee} should be a Load",
            );
        }
    }

    #[test]
    fn cpp_at_is_indexed_load() {
        match classify_container_op("v.at", Lang::Cpp) {
            Some(ContainerOp::Load { index_arg }) => assert_eq!(index_arg, Some(0)),
            other => panic!("expected indexed Load, got {other:?}"),
        }
    }

    /// W5: synthetic `__index_get__` is recognised as an indexed load
    /// in JS/TS, Python, Go, C, and C++, driving the index_arg=0 path so a
    /// constant-key subscript read flows through `HeapSlot::Index(n)`.
    #[test]
    fn synth_index_get_classified_as_indexed_load_for_subscript_languages() {
        for lang in [
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Python,
            Lang::Go,
            Lang::C,
            Lang::Cpp,
        ] {
            match classify_container_op("__index_get__", lang) {
                Some(ContainerOp::Load { index_arg }) => {
                    assert_eq!(index_arg, Some(0), "{lang:?} should mark idx arg=0");
                }
                other => panic!("{lang:?}: expected indexed Load, got {other:?}"),
            }
        }
    }

    /// W5: synthetic `__index_set__` is recognised as an indexed store
    /// in JS/TS, Python, Go, C, and C++, value at arg 1, index at arg 0.
    #[test]
    fn synth_index_set_classified_as_indexed_store_for_subscript_languages() {
        for lang in [
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Python,
            Lang::Go,
            Lang::C,
            Lang::Cpp,
        ] {
            match classify_container_op("__index_set__", lang) {
                Some(ContainerOp::Store {
                    value_args,
                    index_arg,
                }) => {
                    assert_eq!(
                        value_args.as_slice(),
                        &[1],
                        "{lang:?} value arg should be 1"
                    );
                    assert_eq!(index_arg, Some(0), "{lang:?} index arg should be 0");
                }
                other => panic!("{lang:?}: expected indexed Store, got {other:?}"),
            }
        }
    }
}
