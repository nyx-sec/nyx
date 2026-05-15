//! Phase 24 — exploit-chain composer scaffolding (Track G.1).
//!
//! A `ChainGraph` is the small intermediate representation the chain
//! composer walks between two pre-existing artefacts: the flat list of
//! per-finding [`Diag`](crate::commands::scan::Diag)s produced by the
//! static analyser and the [`SurfaceMap`](crate::surface::SurfaceMap)
//! produced by Track F.
//!
//! Phase 24 ships the types only.  The implicit-attacker node and the
//! bounded DFS that walks edges into [`ChainFinding`]s land in Phase 25
//! (`src/chain/search.rs`); composite re-verification lands in Phase 26
//! (`src/chain/reverify.rs`).
//!
//! # Storage shape
//!
//! Two parallel `Vec`s — `nodes` and `edges` — mirroring `SurfaceMap`'s
//! shape.  Determinism is the caller's responsibility: edges are
//! produced in the order the source [`Diag`] slice presents, and
//! `findings_to_edges` does not sort the input.  Phase 25 will fold
//! these into a `petgraph::DiGraph` for path search.
//!
//! # Lattice exhaustiveness
//!
//! [`impact`] keeps a `IMPACT_LATTICE_COVERED | IMPACT_LATTICE_UNCOVERED
//! == Cap::all().bits()` const assertion, mirroring the
//! `CORPUS_SUPPORTED | CORPUS_UNSUPPORTED == Cap::all().bits()` pattern
//! in [`crate::dynamic::corpus`].  Adding a new `Cap` bit without
//! updating the lattice fails to compile.

use crate::entry_points::HttpMethod;
use crate::labels::Cap;
use crate::surface::SourceLocation;
use serde::{Deserialize, Serialize};

pub mod edges;
pub mod feasibility;
pub mod impact;

pub use edges::{ChainEdge, FindingRef, findings_to_edges};
pub use feasibility::Feasibility;
pub use impact::{IMPACT_LATTICE, ImpactCategory, ImpactRule, lookup_impact};

/// One node in a [`ChainGraph`].
///
/// `Entry` and `Sink` nodes are translated 1:1 from the SurfaceMap's
/// [`crate::surface::SurfaceNode::EntryPoint`] and
/// [`crate::surface::SurfaceNode::DangerousLocal`] variants.  `Finding`
/// nodes wrap a static [`Diag`](crate::commands::scan::Diag) so a path
/// from an entry to a sink can pin which finding witnesses each hop.
/// Phase 25's path search treats the implicit attacker as a virtual
/// predecessor of every `Entry`; there is no explicit `Attacker`
/// variant on this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "node", rename_all = "snake_case")]
pub enum ChainNode {
    /// A web entry-point lifted from the SurfaceMap.
    Entry {
        location: SourceLocation,
        method: HttpMethod,
        route: String,
        auth_required: bool,
    },
    /// A static finding produced by the analyser.
    Finding(FindingRef),
    /// A dangerous-local sink lifted from the SurfaceMap.
    Sink {
        location: SourceLocation,
        function_name: String,
        cap_bits: u32,
    },
}

impl ChainNode {
    /// Source location of this node.  Used for byte-deterministic
    /// ordering and for the `nyx surface`-style human display.
    pub fn location(&self) -> &SourceLocation {
        match self {
            ChainNode::Entry { location, .. } => location,
            ChainNode::Finding(f) => &f.location,
            ChainNode::Sink { location, .. } => location,
        }
    }

    /// Cap bitmask carried by this node, or `0` for entry nodes.  Used
    /// by Phase 25 to discriminate which [`ImpactRule`] a path matches.
    pub fn cap_bits(&self) -> u32 {
        match self {
            ChainNode::Entry { .. } => 0,
            ChainNode::Finding(f) => f.cap_bits,
            ChainNode::Sink { cap_bits, .. } => *cap_bits,
        }
    }
}

/// The full chain graph.  Phase 24 only exposes the types; the
/// composer that fills the vectors lands in Phase 25.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChainGraph {
    pub nodes: Vec<ChainNode>,
    pub edges: Vec<ChainEdge>,
}

impl ChainGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

/// Convert a primary [`Cap`] bit into the closest matching impact
/// category in isolation (no adjacency).  Returns `None` when the cap
/// has no terminal interpretation on its own — chain composition needs
/// an additional cap or surface property to lift it.
///
/// Phase 25's path-search code calls this as a fast-path before
/// consulting the full [`IMPACT_LATTICE`].
pub fn standalone_impact(cap: Cap) -> Option<ImpactCategory> {
    IMPACT_LATTICE
        .iter()
        .find(|rule| rule.source_cap == cap && rule.adjacent_cap.is_none())
        .map(|rule| rule.result)
}
