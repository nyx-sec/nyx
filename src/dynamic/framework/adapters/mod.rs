//! Concrete [`super::FrameworkAdapter`] implementations.
//!
//! Phase 03 (Track J.1) lands the first four adapters — one per
//! language carrying the new `Cap::DESERIALIZE` corpus.  Each adapter
//! detects the language's canonical deserialization sink inside a
//! function body and stamps a [`super::FrameworkBinding`] with
//! [`crate::evidence::EntryKind::Function`].  Track L.1+ will register
//! the route / framework adapters; the per-cap sink adapters live here
//! so the per-language verticals can ship independently.

pub mod java_deserialize;
pub mod php_unserialize;
pub mod python_pickle;
pub mod ruby_marshal;

pub use java_deserialize::JavaDeserializeAdapter;
pub use php_unserialize::PhpUnserializeAdapter;
pub use python_pickle::PythonPickleAdapter;
pub use ruby_marshal::RubyMarshalAdapter;

/// True when any callee in `summary.callees` matches `predicate`.
fn any_callee_matches(
    summary: &crate::summary::FuncSummary,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    summary
        .callees
        .iter()
        .any(|c| predicate(c.name.as_str()))
}
