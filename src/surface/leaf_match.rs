//! Callee-name matching shared by the data-store and external-service
//! detectors.
//!
//! Each detector owns an ordered rule table whose entries carry a `leaf`
//! pattern.  A callee matches the first rule, in table order, for which:
//!
//! * a qualified pattern (one containing `.` or `::`) is a substring of
//!   the trimmed, lowercased callee, or
//! * a bare pattern equals one whole segment of the lowercased callee,
//!   with `::` treated as `.`.
//!
//! [`LeafMatcher`] lowercases the patterns once and indexes the bare ones
//! by text, so a lookup costs one lowercase copy of the callee, one hash
//! probe per segment and a substring scan over the qualified patterns
//! that come before the best bare match.

use std::borrow::Cow;

use rustc_hash::FxHashMap;

pub(crate) struct LeafMatcher {
    /// Lowercased bare pattern to the index of the first rule using it.
    bare: FxHashMap<String, usize>,
    /// Lowercased qualified patterns with their rule index, in rule order.
    qualified: Vec<(usize, String)>,
}

impl LeafMatcher {
    /// Index the rule patterns, given in rule order.
    pub(crate) fn new<'a>(leaves: impl IntoIterator<Item = &'a str>) -> Self {
        let mut bare = FxHashMap::default();
        let mut qualified = Vec::new();
        for (idx, leaf) in leaves.into_iter().enumerate() {
            let lower = leaf.to_ascii_lowercase();
            if leaf.contains('.') || leaf.contains("::") {
                qualified.push((idx, lower));
            } else {
                bare.entry(lower).or_insert(idx);
            }
        }
        Self { bare, qualified }
    }

    /// Index of the first rule matching `callee`, if any.
    pub(crate) fn find(&self, callee: &str) -> Option<usize> {
        let lower = callee.trim().to_ascii_lowercase();
        let segments: Cow<'_, str> = if lower.contains("::") {
            Cow::Owned(lower.replace("::", "."))
        } else {
            Cow::Borrowed(&lower)
        };
        let mut best = segments
            .split('.')
            .filter_map(|seg| self.bare.get(seg).copied())
            .min();
        // Every qualified pattern contains `.` or `:`, so a callee with
        // neither cannot contain one.
        if lower.contains(['.', ':']) {
            for (idx, pattern) in &self.qualified {
                if best.is_some_and(|b| b < *idx) {
                    break;
                }
                if lower.contains(pattern.as_str()) {
                    best = Some(*idx);
                    break;
                }
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::LeafMatcher;

    /// The rule-by-rule scan the matcher replaces.
    fn reference(leaves: &[&str], callee: &str) -> Option<usize> {
        let cl = callee.trim().to_ascii_lowercase();
        let cl_segments = cl.replace("::", ".");
        leaves.iter().position(|leaf| {
            let rl = leaf.to_ascii_lowercase();
            if leaf.contains('.') || leaf.contains("::") {
                cl.contains(&rl)
            } else {
                cl_segments.split('.').any(|seg| seg == rl)
            }
        })
    }

    #[test]
    fn matches_the_rule_by_rule_scan() {
        let leaves = [
            "psycopg2.connect",
            "open",
            "Eloquent::find",
            "fetch",
            "requests.get",
            "Open",
            "db.Query",
            "query",
            "redis.NewClient",
        ];
        let matcher = LeafMatcher::new(leaves);
        let callees = [
            "psycopg2.connect",
            "  PSYCOPG2.Connect  ",
            "open",
            "fopen",
            "os.open",
            "Eloquent::find",
            "App\\Eloquent::findOrFail",
            "User::query",
            "window.fetch",
            "prefetch",
            "requests.get_json",
            "my.requests.get",
            "db.Query",
            "tx.db.QueryRow",
            "redis.NewClient",
            "query.open",
            "a::b::open",
            "",
            ":",
            ".",
            "x..open",
            "unrelated",
        ];
        for callee in callees {
            assert_eq!(
                matcher.find(callee),
                reference(&leaves, callee),
                "callee {callee:?}"
            );
        }
    }

    #[test]
    fn earlier_qualified_rule_beats_later_bare_rule() {
        let matcher = LeafMatcher::new(["db.query", "query"]);
        assert_eq!(matcher.find("db.query"), Some(0));
        assert_eq!(matcher.find("x.query"), Some(1));
    }

    #[test]
    fn earlier_bare_rule_beats_later_qualified_rule() {
        let matcher = LeafMatcher::new(["query", "db.query"]);
        assert_eq!(matcher.find("db.query"), Some(0));
    }
}
