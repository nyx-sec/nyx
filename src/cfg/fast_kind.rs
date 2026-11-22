//! Per-file node-kind tables for the CFG builder.
//!
//! `Node::kind()` converts the grammar's C string on every call (a `strlen`
//! plus a UTF-8 check), and the builder asks for the kind of most nodes many
//! times; together with the `labels::lookup` hash of that string this was
//! about a tenth of `cfg_build_large_go`.  While a file's CFG is built,
//! [`install`] keeps the kind names (and their [`Kind`] classes) of the
//! file's grammar in a table indexed by `kind_id()`.  [`FastKind::fkind`] and
//! [`lookup_node`] read it and fall back to the plain calls for any node of
//! another grammar, or when no table is installed.

use crate::labels::{Kind, lookup};
use std::cell::RefCell;
use tree_sitter::{Language, Node};

struct KindTable {
    /// Symbol count of the grammar the table was built for; a node whose
    /// grammar has a different count is never answered from the table.
    count: usize,
    names: Vec<Option<&'static str>>,
    /// Language slug the classes were looked up for.
    slug: String,
    kinds: Vec<Kind>,
}

thread_local! {
    static TABLE: RefCell<Option<KindTable>> = const { RefCell::new(None) };
}

/// Clears the installed table when dropped, so an early return or unwind
/// cannot leave it in place for the next file on this worker thread.
pub(crate) struct KindTableScope {
    _private: (),
}

impl Drop for KindTableScope {
    fn drop(&mut self) {
        TABLE.with(|t| *t.borrow_mut() = None);
    }
}

/// Install the kind table of `language` (classified for `slug`) for the
/// duration of the returned scope.
pub(crate) fn install(language: &Language, slug: &str) -> KindTableScope {
    let count = language.node_kind_count();
    let names: Vec<Option<&'static str>> = (0..count)
        .map(|id| {
            u16::try_from(id)
                .ok()
                .and_then(|id| language.node_kind_for_id(id))
        })
        .collect();
    let kinds = names
        .iter()
        .map(|n| n.map_or(Kind::Other, |n| lookup(slug, n)))
        .collect();
    TABLE.with(|t| {
        *t.borrow_mut() = Some(KindTable {
            count,
            names,
            slug: slug.to_string(),
            kinds,
        });
    });
    KindTableScope { _private: () }
}

/// `Node::kind()` through the installed table.
pub(crate) trait FastKind {
    fn fkind(&self) -> &'static str;
}

impl FastKind for Node<'_> {
    #[inline]
    fn fkind(&self) -> &'static str {
        let id = self.kind_id() as usize;
        TABLE
            .with(|t| {
                let t = t.borrow();
                let t = t.as_ref()?;
                if t.count != self.language().node_kind_count() {
                    return None;
                }
                t.names.get(id).copied().flatten()
            })
            .unwrap_or_else(|| self.kind())
    }
}

/// A node passed by value or by reference (closure arguments are often
/// `&Node` or `&&Node`).
pub(crate) trait NodeArg<'t> {
    fn node(self) -> Node<'t>;
}

impl<'t> NodeArg<'t> for Node<'t> {
    #[inline]
    fn node(self) -> Node<'t> {
        self
    }
}

impl<'t> NodeArg<'t> for &Node<'t> {
    #[inline]
    fn node(self) -> Node<'t> {
        *self
    }
}

impl<'t> NodeArg<'t> for &&Node<'t> {
    #[inline]
    fn node(self) -> Node<'t> {
        **self
    }
}

/// `labels::lookup(lang, node.kind())` through the installed table.
#[inline]
pub(crate) fn lookup_node<'t>(lang: &str, node: impl NodeArg<'t>) -> Kind {
    let node = node.node();
    let id = node.kind_id() as usize;
    TABLE
        .with(|t| {
            let t = t.borrow();
            let t = t.as_ref()?;
            if t.slug != lang || t.count != node.language().node_kind_count() {
                return None;
            }
            t.kinds.get(id).copied()
        })
        .unwrap_or_else(|| lookup(lang, node.kind()))
}
