//! Explicit cross-language call-graph bridge edges.
//!
//! Without an [`InteropEdge`], the call graph resolver never attempts
//! cross-language resolution. This prevents false positives from functions
//! in different languages that happen to share a name.
//!
//! An [`InteropEdge`] maps a [`CallSiteKey`] (caller language, file, function,
//! callee symbol, call ordinal) to a [`FuncKey`] in another language. Ordinal
//! `0` acts as a wildcard matching any call of that name from the given caller.

use crate::symbol::{FuncKey, Lang};

/// Identifies a specific call site within a caller function.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CallSiteKey {
    pub caller_lang: Lang,
    /// Project-relative file path of the caller.
    pub caller_namespace: String,
    /// Enclosing function name at the call site.
    pub caller_func: String,
    /// The identifier at the call site (callee name as written).
    pub callee_symbol: String,
    /// Per-function call ordinal (0-based).  `0` acts as a wildcard during
    /// matching (matches any ordinal).
    pub ordinal: u32,
}

/// An explicit cross-language bridge edge.
///
/// Connects a call site in one language to a function definition in another.
/// Without an `InteropEdge`, cross-language resolution is never attempted ,
/// this prevents false positives from name collisions across languages.
#[derive(Clone, Debug)]
pub struct InteropEdge {
    pub from: CallSiteKey,
    pub to: FuncKey,
}
