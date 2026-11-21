//! Facts that depend only on the text of a call's callee.
//!
//! The taint transfer asks the same text-only questions of every call: is it a
//! process-exit call, an excluded framework call, an integer producer, a URL
//! builder. It asks them on every worklist visit of a block, again when the
//! block is replayed for events, and again in each pass that re-runs the body.
//! Each answer is a pure function of the callee text, the language and two
//! flags of the CFG node, so it is worked out once per distinct input and kept
//! for the thread.

use crate::ssa::type_facts::{self, TypeKind};
use crate::symbol::Lang;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CallTextFacts {
    /// C/C++ free function that ends the process (`exit`, `abort`).
    pub noreturn: bool,
    /// Framework scaffolding (`router.get`) that never carries data.
    pub excluded: bool,
    /// The callee returns an integer (`parseInt`, `len`).
    pub int_producing: bool,
    /// `(path, base)` argument positions when the call builds a URL from a
    /// base and a path.
    pub url_builder: Option<(usize, usize)>,
    /// The call constructs a URL from a single spec: a URL constructor, a
    /// constructor reached through `outer_callee`, or a static factory.
    pub url_single_arg: bool,
}

impl CallTextFacts {
    /// Work the facts out from scratch. `lang` is `None` only for callers
    /// without a language, which get the language-independent facts.
    pub(super) fn compute(
        lang: Option<Lang>,
        callee: &str,
        outer_callee: Option<&str>,
        is_constructor: bool,
    ) -> Self {
        let mut facts = CallTextFacts {
            int_producing: type_facts::is_int_producing_callee(lang, callee),
            ..Default::default()
        };
        let Some(lang) = lang else {
            return facts;
        };
        facts.noreturn = super::is_noreturn_call(lang, callee);
        facts.excluded = crate::labels::is_excluded(lang.as_str(), callee.as_bytes());
        facts.url_builder =
            type_facts::url_builder_arg_indices(lang, callee, outer_callee, is_constructor);
        let is_url_ctor =
            is_constructor && type_facts::constructor_type(lang, callee) == Some(TypeKind::Url);
        let via_outer = outer_callee
            .is_some_and(|oc| type_facts::constructor_type(lang, oc) == Some(TypeKind::Url));
        facts.url_single_arg =
            is_url_ctor || via_outer || type_facts::is_url_single_arg_factory(lang, callee);
        facts
    }
}

/// One cached answer: the inputs besides the callee text, then the facts.
type Variant = (Option<Lang>, Option<String>, bool, CallTextFacts);

thread_local! {
    /// Facts per callee text. A text is nearly always seen with one
    /// `(lang, outer_callee, is_constructor)` combination, so each entry holds
    /// a short list of variants instead of a composite key that would need an
    /// owned `String` per lookup.
    static CALL_TEXT_FACTS: RefCell<FxHashMap<String, SmallVec<[Variant; 1]>>> =
        RefCell::new(FxHashMap::default());
}

/// Soft cap on [`CALL_TEXT_FACTS`]: past it the map is cleared. The facts are
/// pure, so a clear only costs a recompute.
const CACHE_CAP: usize = 1 << 16;

/// Callee texts longer than this are worked out each time rather than kept.
/// Texts that carry a whole callback body can run to kilobytes, and caching
/// them would pin that memory for no reuse.
const MAX_CACHED_TEXT: usize = 256;

/// The [`CallTextFacts`] for a call, served from the per-thread cache.
pub(super) fn call_text_facts(
    lang: Option<Lang>,
    callee: &str,
    outer_callee: Option<&str>,
    is_constructor: bool,
) -> CallTextFacts {
    if callee.len() > MAX_CACHED_TEXT || memo_disabled() {
        return CallTextFacts::compute(lang, callee, outer_callee, is_constructor);
    }
    CALL_TEXT_FACTS.with(|cell| {
        if let Some(variants) = cell.borrow().get(callee)
            && let Some(hit) = variants.iter().find(|(l, o, c, _)| {
                *l == lang && o.as_deref() == outer_callee && *c == is_constructor
            })
        {
            return hit.3;
        }
        let facts = CallTextFacts::compute(lang, callee, outer_callee, is_constructor);
        let mut map = cell.borrow_mut();
        if map.len() >= CACHE_CAP {
            map.clear();
        }
        map.entry(callee.to_string()).or_default().push((
            lang,
            outer_callee.map(str::to_string),
            is_constructor,
            facts,
        ));
        facts
    })
}

/// `NYX_DISABLE_CALL_TEXT_MEMO=1` computes the facts on every call, to compare
/// the cached and uncached paths from one binary. Read once per process.
fn memo_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var("NYX_DISABLE_CALL_TEXT_MEMO")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALLEES: &[&str] = &[
        "exit",
        "abort",
        "transaction.abort",
        "app.exit",
        "router.get",
        "app.post",
        "parseInt",
        "Integer.parseInt",
        "s.parse::<u32>().unwrap",
        "s.parse::<PathBuf>().unwrap",
        "v.len",
        "items.size",
        "URL",
        "new URL",
        "urljoin",
        "urllib.parse.urljoin",
        "url.JoinPath",
        "URI.join",
        "Url::parse",
        "Url::parse.unwrap",
        "java.net.URL",
        "URI.create",
        "fetch",
        "res.send",
        "a.b(c).d",
        "",
    ];

    const LANGS: &[Option<Lang>] = &[
        None,
        Some(Lang::C),
        Some(Lang::Cpp),
        Some(Lang::Java),
        Some(Lang::JavaScript),
        Some(Lang::TypeScript),
        Some(Lang::Python),
        Some(Lang::Go),
        Some(Lang::Ruby),
        Some(Lang::Rust),
        Some(Lang::Php),
    ];

    /// Every answer from the cache, first and second time, equals the answer
    /// worked out directly, for each combination of the inputs.
    #[test]
    fn cached_facts_equal_computed_facts() {
        for pass in 0..2 {
            for &lang in LANGS {
                for &callee in CALLEES {
                    for outer in [None, Some("URL"), Some("helper")] {
                        for is_ctor in [false, true] {
                            assert_eq!(
                                call_text_facts(lang, callee, outer, is_ctor),
                                CallTextFacts::compute(lang, callee, outer, is_ctor),
                                "pass {pass}: {lang:?} {callee:?} {outer:?} {is_ctor}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn facts_cover_the_cases_they_exist_for() {
        let exit = call_text_facts(Some(Lang::C), "exit", None, false);
        assert!(exit.noreturn);
        // Only C and C++ have process-exit free functions in this table.
        assert!(!call_text_facts(Some(Lang::Python), "exit", None, false).noreturn);
        // A receiver-qualified `abort` is an ordinary call.
        assert!(!call_text_facts(Some(Lang::C), "transaction.abort", None, false).noreturn);

        assert!(call_text_facts(None, "parseInt", None, false).int_producing);
        assert!(!call_text_facts(None, "res.send", None, false).int_producing);

        let ctor = call_text_facts(Some(Lang::JavaScript), "URL", None, true);
        assert!(ctor.url_single_arg);
        assert!(ctor.url_builder.is_some());
        // The constructor can also be reached through `outer_callee` when the
        // visible callee was rewritten to a source path.
        let via_outer =
            call_text_facts(Some(Lang::JavaScript), "req.query.base", Some("URL"), true);
        assert!(via_outer.url_single_arg);
        assert!(!call_text_facts(Some(Lang::JavaScript), "fetch", None, false).url_single_arg);
    }

    #[test]
    fn a_long_callee_text_is_not_kept() {
        let long = format!("wrap({}).then", "x".repeat(MAX_CACHED_TEXT * 2));
        let before = CALL_TEXT_FACTS.with(|c| c.borrow().len());
        let facts = call_text_facts(Some(Lang::JavaScript), &long, None, false);
        assert_eq!(
            facts,
            CallTextFacts::compute(Some(Lang::JavaScript), &long, None, false)
        );
        assert_eq!(CALL_TEXT_FACTS.with(|c| c.borrow().len()), before);
    }
}
