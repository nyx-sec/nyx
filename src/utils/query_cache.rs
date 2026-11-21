use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use tree_sitter::{Language, Query};

use crate::patterns::{self, Pattern};

#[derive(Clone)]
pub struct CompiledQuery {
    pub meta: Pattern,
    pub query: Arc<Query>,
}

type QuerySet = Arc<Vec<CompiledQuery>>;

/// Cache key: the language slug plus the grammar the queries were compiled
/// against.  One slug can map to several grammars (`typescript` covers both
/// the TypeScript and the TSX grammar), and a `Query` only matches trees from
/// the grammar it was compiled for, so the slug alone is not enough.
type CacheKey = (&'static str, Language);

static CACHE: LazyLock<RwLock<HashMap<CacheKey, QuerySet>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Return **one shared Arc** to the per-language query set.
/// Cloning the `Arc` is O(1) and the underlying Vec lives for the
/// lifetime of the process.
///
/// Malformed tree-sitter queries do not panic: each invalid pattern is
/// dropped via `filter_map` with a warn-level log, and the remaining
/// patterns for the language are cached normally. A language with an
/// all-malformed pattern slice yields an empty cache entry.
///
/// Lock poisoning on the shared cache is recovered transparently, a
/// panic in another thread must not brick pattern loading process-wide.
pub fn for_lang(lang: &'static str, ts_lang: Language) -> std::sync::Arc<Vec<CompiledQuery>> {
    let key = (lang, ts_lang);
    // fast path
    if let Some(v) = CACHE.read().unwrap_or_else(|p| p.into_inner()).get(&key) {
        return v.clone();
    }
    let ts_lang = &key.1;

    // slow path, compile
    let patterns = patterns::load(lang);
    let compiled: Vec<_> = patterns
        .into_iter()
        .filter_map(|p| match Query::new(ts_lang, p.query) {
            Ok(q) => Some(CompiledQuery {
                meta: p,
                query: std::sync::Arc::new(q),
            }),
            Err(e) => {
                tracing::warn!(lang, id = p.id, "query compile error: {e}");
                None
            }
        })
        .collect();

    let compiled = std::sync::Arc::new(compiled);

    let mut w = CACHE.write().unwrap_or_else(|p| p.into_inner());
    w.entry(key).or_insert_with(|| compiled.clone()).clone()
}

/// One pattern's metadata inside a [`CombinedQuery`], indexed by the pattern's
/// position in the combined query (`QueryMatch::pattern_index`).
#[derive(Clone)]
pub struct CombinedSlot {
    pub meta: Pattern,
    /// Global capture index (within the combined query) of this pattern's
    /// *primary* capture — the capture that was index 0 in the original
    /// single-rule query. `run_ast_queries` anchors both the Layer A–H
    /// recognisers and the finding span on this capture's node, exactly as the
    /// legacy per-query path keyed on `c.index == 0`. `u32::MAX` when the
    /// original rule declared no captures (then a match yields no diag,
    /// mirroring the legacy `find(c.index == 0)` returning `None`).
    pub primary_capture_index: u32,
}

/// A single tree-sitter query holding **every** pattern rule for a language.
///
/// Running one combined multi-pattern query walks the AST **once** and lets
/// tree-sitter's matcher test all rules in a single pass, instead of the
/// legacy path that issues one `QueryCursor::matches` (== one full tree walk)
/// per rule — `O(rules × nodes)` traversal collapses to `O(nodes)`.
pub struct CombinedQuery {
    pub query: Query,
    /// `slots[pattern_index]` → that pattern's rule metadata + primary capture.
    /// Length equals `query.pattern_count()`.
    pub slots: Vec<CombinedSlot>,
    /// Capture index of `@vuln`, the whole matched node every rule names.
    /// Captures share one name table across the combined query, so one index
    /// serves every pattern.  Layer A reads the matched call from it when the
    /// primary capture sits inside a nested call (see `ast_query_diag`).
    pub vuln_capture_index: Option<u32>,
}

type CombinedSet = Arc<Option<CombinedQuery>>;
static COMBINED_CACHE: LazyLock<RwLock<HashMap<CacheKey, CombinedSet>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Return a process-lifetime [`CombinedQuery`] for `lang`, or `None` when no
/// combined query could be built (no patterns, or the concatenated source
/// failed to compile — e.g. exceeds tree-sitter's capture/pattern limits). The
/// caller falls back to the legacy per-rule loop in that case.
///
/// Built from the already-malformed-filtered per-rule set returned by
/// [`for_lang`], so a single bad rule never poisons the combined query: it was
/// already dropped upstream and simply never enters the concatenation.
pub fn combined_for_lang(lang: &'static str, ts_lang: Language) -> CombinedSet {
    let key = (lang, ts_lang);
    if let Some(v) = COMBINED_CACHE
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(&key)
    {
        return v.clone();
    }

    let built = Arc::new(build_combined(lang, key.1.clone()));

    let mut w = COMBINED_CACHE.write().unwrap_or_else(|p| p.into_inner());
    w.entry(key).or_insert_with(|| built.clone()).clone()
}

fn build_combined(lang: &'static str, ts_lang: Language) -> Option<CombinedQuery> {
    let per = for_lang(lang, ts_lang.clone());
    if per.is_empty() {
        return None;
    }

    // Concatenate every rule's query source (in registry order, so the
    // combined `pattern_index` lines up with `per_pattern`). The primary
    // capture *name* per contributed pattern is the rule's index-0 capture —
    // `capture_names()[0]` — which the legacy path anchors on via
    // `find(c.index == 0)`.
    let mut combined_src = String::new();
    // Own the primary capture name: `capture_names()` borrows from `per`'s
    // per-rule `Query`s, which are dropped at function exit, so a borrowed
    // `&str` cannot survive into the returned slots.
    let mut per_pattern: Vec<(Pattern, Option<String>)> = Vec::new();
    for cq in per.iter() {
        let primary_name = cq.query.capture_names().first().map(|s| s.to_string());
        // A rule's source may technically contain >1 top-level pattern; each
        // contributes one `pattern_index`, all sharing this rule's metadata and
        // index-0 capture name (faithful to the legacy per-rule `c.index == 0`).
        for _ in 0..cq.query.pattern_count() {
            per_pattern.push((cq.meta.clone(), primary_name.clone()));
        }
        combined_src.push_str(cq.meta.query);
        combined_src.push('\n');
    }

    let combined = Query::new(&ts_lang, &combined_src).ok()?;
    // Invariant: combined pattern order == concatenation order. If tree-sitter
    // ever disagrees, bail to the legacy path rather than mis-attribute rules.
    if combined.pattern_count() != per_pattern.len() {
        tracing::warn!(
            lang,
            combined = combined.pattern_count(),
            expected = per_pattern.len(),
            "combined query pattern count mismatch; using legacy per-rule path"
        );
        return None;
    }

    let slots = per_pattern
        .into_iter()
        .map(|(meta, primary_name)| {
            let primary_capture_index = primary_name
                .and_then(|n| combined.capture_index_for_name(&n))
                .unwrap_or(u32::MAX);
            CombinedSlot {
                meta,
                primary_capture_index,
            }
        })
        .collect();

    let vuln_capture_index = combined.capture_index_for_name("vuln");
    Some(CombinedQuery {
        query: combined,
        slots,
        vuln_capture_index,
    })
}

#[cfg(test)]
mod combined_tests {
    use super::*;
    use tree_sitter::{Parser, QueryCursor, StreamingIterator};

    /// `(rule_id, primary-capture start byte)` for every match of the legacy
    /// one-query-per-rule path — the exact `(meta, anchor)` pairs that drive
    /// `ast_query_diag` (and thus the diag set).
    fn legacy_matches(
        lang: &'static str,
        ts: tree_sitter::Language,
        src: &[u8],
    ) -> Vec<(String, usize)> {
        let per = for_lang(lang, ts.clone());
        let mut parser = Parser::new();
        parser.set_language(&ts).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let root = tree.root_node();
        let mut cursor = QueryCursor::new();
        let mut out = Vec::new();
        for cq in per.iter() {
            let mut m = cursor.matches(&cq.query, root, src);
            while let Some(mat) = m.next() {
                if let Some(cap) = mat.captures.iter().find(|c| c.index == 0) {
                    out.push((cq.meta.id.to_owned(), cap.node.start_byte()));
                }
            }
        }
        out.sort();
        out
    }

    /// Same `(rule_id, anchor)` pairs, derived from the combined query via
    /// `slot.meta` + `slot.primary_capture_index`.
    fn combined_matches(
        lang: &'static str,
        ts: tree_sitter::Language,
        src: &[u8],
    ) -> Vec<(String, usize)> {
        let combined = combined_for_lang(lang, ts.clone());
        let cq = combined.as_ref().as_ref().expect("combined query built");
        let mut parser = Parser::new();
        parser.set_language(&ts).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let root = tree.root_node();
        let mut cursor = QueryCursor::new();
        let mut out = Vec::new();
        let mut m = cursor.matches(&cq.query, root, src);
        while let Some(mat) = m.next() {
            let slot = &cq.slots[mat.pattern_index];
            if let Some(cap) = mat
                .captures
                .iter()
                .find(|c| c.index == slot.primary_capture_index)
            {
                out.push((slot.meta.id.to_owned(), cap.node.start_byte()));
            }
        }
        out.sort();
        out
    }

    fn assert_equiv(lang: &'static str, ts: tree_sitter::Language, src: &[u8]) {
        let legacy = legacy_matches(lang, ts.clone(), src);
        let combined = combined_matches(lang, ts, src);
        assert_eq!(
            combined, legacy,
            "combined query must yield the same (rule, anchor) set as the legacy per-rule path for {lang}"
        );
        assert!(
            !legacy.is_empty(),
            "fixture should trigger ≥1 rule for {lang}"
        );
    }

    #[test]
    fn combined_query_pattern_count_matches_per_rule_sum() {
        for (lang, ts) in [
            ("go", tree_sitter_go::LANGUAGE.into()),
            ("javascript", tree_sitter_javascript::LANGUAGE.into()),
            ("python", tree_sitter_python::LANGUAGE.into()),
        ] {
            let ts: tree_sitter::Language = ts;
            let per = for_lang(lang, ts.clone());
            let expected: usize = per.iter().map(|cq| cq.query.pattern_count()).sum();
            let combined = combined_for_lang(lang, ts);
            let cq = combined.as_ref().as_ref().expect("combined query built");
            assert_eq!(cq.query.pattern_count(), expected, "{lang} pattern count");
            assert_eq!(cq.slots.len(), expected, "{lang} slot count");
            // Every real rule declares a capture, so every slot must resolve one.
            assert!(
                cq.slots.iter().all(|s| s.primary_capture_index != u32::MAX),
                "{lang} every slot resolves its primary capture"
            );
        }
    }

    #[test]
    fn combined_matches_legacy_go() {
        let src = b"package main\nimport (\"os/exec\"\n\"crypto/md5\")\nfunc f(u string) {\n  exec.Command(u)\n  md5.New()\n  c := &tls.Config{InsecureSkipVerify: true}\n  _ = c\n}\n";
        assert_equiv("go", tree_sitter_go::LANGUAGE.into(), src);
    }

    #[test]
    fn combined_matches_legacy_javascript() {
        let src = b"function f(x) {\n  eval(x);\n  document.write(x);\n  el.innerHTML = x;\n}\n";
        assert_equiv("javascript", tree_sitter_javascript::LANGUAGE.into(), src);
    }

    #[test]
    fn combined_matches_legacy_python() {
        let src = b"import pickle, subprocess\ndef f(x):\n    eval(x)\n    pickle.loads(x)\n    subprocess.call(x, shell=True)\n";
        assert_equiv("python", tree_sitter_python::LANGUAGE.into(), src);
    }

    /// `.ts` and `.tsx` files share the `typescript` slug but parse with
    /// different grammars, whose node-kind ids differ.  A query compiled for
    /// one grammar matches nothing on the other's trees, so whichever grammar
    /// filled a slug-keyed cache first silenced every AST rule for the other
    /// file type, and parallel scans flipped between the two outcomes.
    #[test]
    fn typescript_and_tsx_grammars_get_their_own_query_sets() {
        let src = b"function f(x: any) {\n  const y = x as any;\n  eval(y);\n}\n";
        let ts: tree_sitter::Language = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
        let tsx: tree_sitter::Language = tree_sitter_typescript::LANGUAGE_TSX.into();
        for (first, second) in [(&ts, &tsx), (&tsx, &ts)] {
            for grammar in [first, second] {
                assert_equiv("typescript", grammar.clone(), src);
                let hits = legacy_matches("typescript", grammar.clone(), src);
                assert!(
                    hits.iter().any(|(id, _)| id == "ts.quality.as_any"),
                    "as_any must fire under every TypeScript grammar, got {hits:?}"
                );
            }
        }
        assert!(!Arc::ptr_eq(
            &for_lang("typescript", ts.clone()),
            &for_lang("typescript", tsx.clone())
        ));
    }
}
