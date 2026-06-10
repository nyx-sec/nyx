//! Phase 21 — attack-surface map.
//!
//! The `SurfaceMap` graph names the externally-reachable shape of the
//! project under analysis: HTTP route entry-points (Flask, FastAPI,
//! Spring, Express, …), the data stores they read/write, the external
//! services they talk to, and the local sinks they ultimately reach.
//!
//! Track G's chain composer walks this graph to translate findings into
//! cross-feature attack chains, and the `nyx surface` CLI prints a
//! human-readable tree from it.  Phase 21 ships the graph types plus
//! the first framework probe (Python + Flask); Phase 22 generalises the
//! probe to the remaining languages and Phase 23 wires the CLI.
//!
//! Storage shape: a flat `Vec<SurfaceNode>` sorted by [`SourceLocation`]
//! and a flat `Vec<SurfaceEdge>` sorted by `(from_idx, to_idx, kind)`.
//! Both vectors are byte-deterministic, so two scans of the same source
//! produce byte-identical JSON when round-tripped through SQLite.  See
//! [`graph::petgraph_view`] for a petgraph-backed view used by the
//! chain composer.

use crate::entry_points::HttpMethod;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub mod build;
pub mod dangerous;
pub mod datastore;
pub mod exposure;
pub mod external;
pub mod graph;
pub mod lang;
pub mod reachability;
pub mod risk;

/// Stable source location used as the primary key for every
/// [`SurfaceNode`].  `file` is a project-relative POSIX path so the
/// SurfaceMap is portable across machines; `line` and `col` are
/// 1-indexed.  Ordering is `(file, line, col)` lexicographic, matching
/// the determinism the rest of the analyser uses for spans.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub col: u32,
}

impl SourceLocation {
    pub fn new(file: impl Into<String>, line: u32, col: u32) -> Self {
        Self {
            file: file.into(),
            line,
            col,
        }
    }
}

/// Web-framework tag attached to every [`EntryPoint`].  The set is
/// fixed in Phase 21 + 22 and matches the set of framework probes
/// behind [`lang`].  New frameworks land as new variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    Flask,
    FastApi,
    Django,
    Express,
    Koa,
    Spring,
    JaxRs,
    Quarkus,
    Rails,
    Sinatra,
    Laravel,
    Slim,
    Axum,
    Actix,
    Rocket,
    NetHttp,
    Gin,
    NextAppRouter,
    NextServerAction,
}

/// HTTP-handler entry-point recognised by a framework probe.
///
/// Every node carries the route's declared path string, HTTP method,
/// and a resolved handler [`SourceLocation`] pointing at the function
/// definition.  `auth_required` is `true` when the decorator stack
/// (or framework equivalent) contains an auth guard the probe was
/// able to identify; Phase 21 recognises Flask's `@login_required`,
/// `@auth_required`, and `@jwt_required` decorators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPoint {
    pub location: SourceLocation,
    pub framework: Framework,
    pub method: HttpMethod,
    pub route: String,
    pub handler_name: String,
    pub handler_location: SourceLocation,
    pub auth_required: bool,
}

/// Persistent data store reachable from the surface — SQL database,
/// key-value store, document DB, blob store.  Phase 22 populates this
/// from label-rule data-source matches and ORM-receiver type facts;
/// Phase 21 ships the type for forward-compat only and emits no
/// `DataStore` nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataStore {
    pub location: SourceLocation,
    pub kind: DataStoreKind,
    pub label: String,
    /// Qualified name of the function that owns this access site
    /// (`Class::method` or a free function name).  Used by reachability
    /// to connect an entry-point to this store only when the owning
    /// function is actually on the call-graph frontier, rather than the
    /// coarse "any node in the same file" match.  Empty for legacy maps
    /// loaded from SQLite before the field landed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner: String,
    /// Whether the access site reads, writes, or does both, classified
    /// from the callee name at detection time (`find`/`get`/`select` →
    /// read, `insert`/`save`/`delete` → write, `execute`/`exec` →
    /// read-write).  Drives the [`EdgeKind::ReadsFrom`] /
    /// [`EdgeKind::WritesTo`] split in reachability.  `Unknown` for
    /// connect-style sites and legacy maps loaded from SQLite before
    /// the field landed.
    #[serde(default, skip_serializing_if = "AccessMode::is_unknown")]
    pub access: AccessMode,
}

/// Direction of a data-store access site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Read,
    Write,
    ReadWrite,
    #[default]
    Unknown,
}

impl AccessMode {
    /// Serde helper: `Unknown` is the default and is omitted from the
    /// canonical JSON so legacy payloads stay byte-identical.
    pub fn is_unknown(&self) -> bool {
        matches!(self, AccessMode::Unknown)
    }

    /// True when the site can write (Write or ReadWrite).
    pub fn writes(self) -> bool {
        matches!(self, AccessMode::Write | AccessMode::ReadWrite)
    }

    /// True when the site can read (Read, ReadWrite, or Unknown — an
    /// unclassified site is conservatively treated as a read).
    pub fn reads(self) -> bool {
        !matches!(self, AccessMode::Write)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataStoreKind {
    Sql,
    KeyValue,
    Document,
    BlobStore,
    Filesystem,
    Unknown,
}

/// External service the surface talks to over a network — third-party
/// HTTP API, message broker, search index.  Phase 22 fills this in;
/// Phase 21 ships the type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalService {
    pub location: SourceLocation,
    pub kind: ExternalServiceKind,
    pub label: String,
    /// Qualified name of the function that owns this egress site.  See
    /// [`DataStore::owner`] for why reachability needs it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalServiceKind {
    HttpApi,
    MessageBroker,
    SearchIndex,
    AuthProvider,
    Unknown,
}

/// Local sink with no externally observable side-effect — `eval`,
/// `pickle.loads`, `subprocess.Popen`, raw SQL execute, etc.  Phase 22
/// fills this in from the existing label-rule registry; Phase 21
/// ships the type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DangerousLocal {
    pub location: SourceLocation,
    pub function_name: String,
    pub cap_bits: u32,
    /// Human-readable sink-class label decoded from `cap_bits`
    /// (e.g. `"code-exec"`, `"deserialize, ssti"`).  Lets the CLI and
    /// the chain composer name the danger without re-deriving it from
    /// the raw bitfield.  Empty for legacy maps loaded from SQLite
    /// before the field landed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
}

/// A node in the [`SurfaceMap`].  Every variant carries a
/// [`SourceLocation`] so the surface ordering is total and stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "node", rename_all = "snake_case")]
pub enum SurfaceNode {
    EntryPoint(EntryPoint),
    DataStore(DataStore),
    ExternalService(ExternalService),
    DangerousLocal(DangerousLocal),
}

impl SurfaceNode {
    pub fn location(&self) -> &SourceLocation {
        match self {
            SurfaceNode::EntryPoint(n) => &n.location,
            SurfaceNode::DataStore(n) => &n.location,
            SurfaceNode::ExternalService(n) => &n.location,
            SurfaceNode::DangerousLocal(n) => &n.location,
        }
    }

    /// Discriminator used as a secondary sort key so two nodes that
    /// happen to share a [`SourceLocation`] (e.g. multiple route
    /// decorators on one function) keep a deterministic relative
    /// order.  Returns the variant index in the enum declaration.
    fn kind_ordinal(&self) -> u8 {
        match self {
            SurfaceNode::EntryPoint(_) => 0,
            SurfaceNode::DataStore(_) => 1,
            SurfaceNode::ExternalService(_) => 2,
            SurfaceNode::DangerousLocal(_) => 3,
        }
    }

    /// Tertiary sort key used to disambiguate nodes that share both
    /// [`SourceLocation`] and kind — e.g. a single Flask function with
    /// two `@app.route(...)` decorators ending up at the same handler
    /// location.
    fn dedup_tag(&self) -> String {
        match self {
            SurfaceNode::EntryPoint(n) => format!("{:?}:{:?}:{}", n.framework, n.method, n.route),
            SurfaceNode::DataStore(n) => format!("{:?}:{}", n.kind, n.label),
            SurfaceNode::ExternalService(n) => format!("{:?}:{}", n.kind, n.label),
            SurfaceNode::DangerousLocal(n) => format!("{}:{:#x}", n.function_name, n.cap_bits),
        }
    }
}

/// Semantic kind of an edge in the [`SurfaceMap`].
///
/// Persistence is via JSON so adding a variant is a non-breaking schema
/// change as long as the SQLite-level migration drops the old
/// surface_map rows.
///
/// Emission status (kept honest so the next maintainer does not inherit
/// a false mental model):
///
/// * **Emitted today** by [`reachability::populate_reaches_edges`]:
///   [`EdgeKind::ReadsFrom`] (entry → data store the entry reads),
///   [`EdgeKind::WritesTo`] (entry → data store the entry writes,
///   from [`DataStore::access`]), [`EdgeKind::TalksTo`] (entry →
///   external service), and [`EdgeKind::Reaches`] (entry →
///   dangerous-local sink). These four are [`EdgeKind::is_reach_like`].
/// * **Reserved** (no production construction site yet):
///   [`EdgeKind::Calls`] (would lift call-graph edges, currently
///   redundant with the [`crate::callgraph::CallGraph`] itself),
///   [`EdgeKind::Triggers`] (needs job/webhook entry modelling), and
///   [`EdgeKind::AuthRequiredOn`] (needs a dedicated auth-check node
///   to originate from — today the auth signal rides on
///   [`EntryPoint::auth_required`] instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Caller → callee.  Wraps the call-graph edge so consumers do
    /// not have to consult [`crate::callgraph::CallGraph`] directly.
    /// Reserved — not emitted.
    Calls,
    /// Entry-point reads from a data store.  Emitted by reachability.
    ReadsFrom,
    /// Entry-point writes to a data store.  Emitted by reachability
    /// when [`DataStore::access`] classifies the site as writing.
    WritesTo,
    /// Entry-point sends a request to an external service.  Emitted by
    /// reachability.
    TalksTo,
    /// Entry-point reaches a dangerous-local sink through some
    /// transitive call chain.  Emitted by reachability.
    Reaches,
    /// Entry-point triggers a side-effecting action (job, email,
    /// webhook) other than a direct call.  Reserved.
    Triggers,
    /// Entry-point gates downstream access on a successful auth
    /// check.  The `from` is the auth-check node, the `to` is the
    /// entry-point.  Reserved — needs an auth-check node.
    AuthRequiredOn,
}

impl EdgeKind {
    /// True for the edge classes that connect an entry-point to a
    /// reachable sink / store / external service.  The CLI tree and any
    /// "what does this entry reach" query treat all three uniformly.
    pub fn is_reach_like(self) -> bool {
        matches!(
            self,
            EdgeKind::Reaches | EdgeKind::ReadsFrom | EdgeKind::TalksTo | EdgeKind::WritesTo
        )
    }
}

/// Decode a [`crate::labels::Cap`] bitfield into a stable, human-readable
/// list of sink-class slugs (e.g. `0x400` → `["code-exec"]`).  Order is
/// fixed (low bit first) so two equal bitfields render identically.
/// Used for [`DangerousLocal::label`] and the `nyx surface` CLI so the
/// raw `0x{:x}` debug dump never reaches a user.
pub fn cap_labels(bits: u32) -> Vec<&'static str> {
    use crate::labels::Cap;
    const TABLE: &[(Cap, &str)] = &[
        (Cap::CODE_EXEC, "code-exec"),
        (Cap::DESERIALIZE, "deserialize"),
        (Cap::SSTI, "ssti"),
        (Cap::FMT_STRING, "format-string"),
        (Cap::SQL_QUERY, "sql"),
        (Cap::SSRF, "ssrf"),
        (Cap::FILE_IO, "file-io"),
        (Cap::LDAP_INJECTION, "ldap-injection"),
        (Cap::XPATH_INJECTION, "xpath-injection"),
        (Cap::HEADER_INJECTION, "header-injection"),
        (Cap::OPEN_REDIRECT, "open-redirect"),
        (Cap::XXE, "xxe"),
        (Cap::PROTOTYPE_POLLUTION, "prototype-pollution"),
        (Cap::CRYPTO, "weak-crypto"),
        (Cap::DATA_EXFIL, "data-exfil"),
        (Cap::UNAUTHORIZED_ID, "unauthorized-id"),
    ];
    let caps = Cap::from_bits_truncate(bits);
    let mut out: Vec<&'static str> = TABLE
        .iter()
        .filter(|(c, _)| caps.contains(*c))
        .map(|(_, s)| *s)
        .collect();
    if out.is_empty() {
        out.push("sink");
    }
    out
}

/// Comma-joined form of [`cap_labels`].
pub fn cap_label_string(bits: u32) -> String {
    cap_labels(bits).join(", ")
}

/// A single edge in the [`SurfaceMap`].  `from` and `to` are indices
/// into [`SurfaceMap::nodes`]; the surface ordering keeps these
/// stable across rescans.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct SurfaceEdge {
    pub from: u32,
    pub to: u32,
    pub kind: EdgeKind,
}

/// The attack-surface graph for a project.  Stored as parallel
/// `Vec`s keyed on [`SourceLocation`] so JSON serialisation is
/// byte-deterministic and SQLite round-trips are stable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceMap {
    pub nodes: Vec<SurfaceNode>,
    pub edges: Vec<SurfaceEdge>,
}

impl SurfaceMap {
    /// Construct an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total node count.  Cheap.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total edge count.  Cheap.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Return the first entry-point node matching `(method, route)`.
    /// Linear scan; the SurfaceMap is small (one node per route +
    /// store + service + sink) so this is fine in practice.
    pub fn entry_for_route(&self, method: HttpMethod, route: &str) -> Option<&EntryPoint> {
        self.nodes.iter().find_map(|n| match n {
            SurfaceNode::EntryPoint(ep) if ep.method == method && ep.route == route => Some(ep),
            _ => None,
        })
    }

    /// Iterate over every entry-point node in surface order.
    pub fn entry_points(&self) -> impl Iterator<Item = &EntryPoint> {
        self.nodes.iter().filter_map(|n| match n {
            SurfaceNode::EntryPoint(ep) => Some(ep),
            _ => None,
        })
    }

    /// Sort nodes by `(SourceLocation, kind_ordinal, dedup_tag)` and
    /// rewrite every edge's `from`/`to` accordingly.  Two structurally
    /// identical maps are byte-identical after [`canonicalize`] +
    /// `serde_json::to_vec` regardless of insertion order.
    ///
    /// [`canonicalize`]: SurfaceMap::canonicalize
    pub fn canonicalize(&mut self) {
        if self.nodes.is_empty() {
            self.edges.sort();
            self.edges.dedup();
            return;
        }
        let mut indexed: Vec<(usize, &SurfaceNode)> = self.nodes.iter().enumerate().collect();
        indexed.sort_by(|(_, a), (_, b)| {
            let key_a = (a.location(), a.kind_ordinal(), a.dedup_tag());
            let key_b = (b.location(), b.kind_ordinal(), b.dedup_tag());
            key_a.cmp(&key_b)
        });
        let mut remap: BTreeMap<u32, u32> = BTreeMap::new();
        let mut new_nodes: Vec<SurfaceNode> = Vec::with_capacity(self.nodes.len());
        for (new_idx, (old_idx, _)) in indexed.iter().enumerate() {
            remap.insert(*old_idx as u32, new_idx as u32);
        }
        for (_, node) in indexed {
            new_nodes.push(node.clone());
        }
        for edge in &mut self.edges {
            if let Some(&new_from) = remap.get(&edge.from) {
                edge.from = new_from;
            }
            if let Some(&new_to) = remap.get(&edge.to) {
                edge.to = new_to;
            }
        }
        self.nodes = new_nodes;
        self.edges.sort();
        self.edges.dedup();
    }

    /// Serialize to deterministic JSON.  The map is canonicalised
    /// first; structurally identical maps emit byte-identical JSON.
    pub fn to_json(&mut self) -> serde_json::Result<Vec<u8>> {
        self.canonicalize();
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON.  Does not canonicalise; the producer is
    /// responsible for emitting a canonicalised payload.
    pub fn from_json(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }
}

/// Strip the optional `@pkg/name::` package prefix from a [`crate::symbol::FuncKey`]
/// namespace, returning the project-relative POSIX file path part.
///
/// `namespace_with_package` produces `"@scope/name::src/file.ts"` for
/// JS/TS files inside resolved packages; the file part is the
/// project-relative path that matches an [`EntryPoint`]'s
/// `handler_location.file`.  This is the single source of truth the
/// detectors and the reachability pass both key on, so a data-store /
/// external / dangerous-local node and the entry-point that reaches it
/// agree on file identity even though `FuncSummary.file_path` is stored
/// as an absolute path.
pub fn namespace_file(ns: &str) -> &str {
    ns.rsplit_once("::").map(|(_, rest)| rest).unwrap_or(ns)
}

/// Convert an absolute path to a project-relative POSIX path string.
/// Returns the absolute path verbatim when the file is outside the
/// scan root or when path stripping fails.
pub fn relative_path_string(path: &Path, scan_root: Option<&Path>) -> String {
    if let Some(root) = scan_root
        && let Ok(rel) = path.strip_prefix(root)
    {
        return rel.to_string_lossy().replace('\\', "/");
    }
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(file: &str, line: u32, col: u32) -> SourceLocation {
        SourceLocation::new(file, line, col)
    }

    fn ep(file: &str, line: u32, route: &str, method: HttpMethod) -> SurfaceNode {
        SurfaceNode::EntryPoint(EntryPoint {
            location: loc(file, line, 1),
            framework: Framework::Flask,
            method,
            route: route.into(),
            handler_name: "h".into(),
            handler_location: loc(file, line + 1, 1),
            auth_required: false,
        })
    }

    #[test]
    fn canonicalize_sorts_nodes_and_remaps_edges() {
        let mut m = SurfaceMap::new();
        m.nodes.push(ep("b.py", 10, "/b", HttpMethod::GET));
        m.nodes.push(ep("a.py", 5, "/a", HttpMethod::GET));
        m.edges.push(SurfaceEdge {
            from: 0,
            to: 1,
            kind: EdgeKind::Calls,
        });
        m.canonicalize();
        assert_eq!(m.nodes[0].location().file, "a.py");
        assert_eq!(m.nodes[1].location().file, "b.py");
        // edge `from=0` was b.py (now index 1), `to=1` was a.py (now index 0)
        assert_eq!(m.edges[0].from, 1);
        assert_eq!(m.edges[0].to, 0);
    }

    #[test]
    fn json_round_trip_byte_identical() {
        let mut a = SurfaceMap::new();
        a.nodes.push(ep("a.py", 1, "/a", HttpMethod::GET));
        a.nodes.push(ep("b.py", 2, "/b", HttpMethod::POST));
        a.edges.push(SurfaceEdge {
            from: 0,
            to: 1,
            kind: EdgeKind::Calls,
        });
        let bytes_a = a.to_json().unwrap();
        let b = SurfaceMap::from_json(&bytes_a).unwrap();
        let mut b = b;
        let bytes_b = b.to_json().unwrap();
        assert_eq!(bytes_a, bytes_b);
    }
}
