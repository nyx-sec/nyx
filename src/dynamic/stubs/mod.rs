//! Per-cap stub providers (Phase 10 — Track D.3).
//!
//! A *stub* is a tiny in-process service that pretends to be the real
//! boundary a sink crosses — a SQL server, an HTTP origin, a Redis
//! cache, a writable filesystem root — so a sink that talks to that
//! boundary can fire under test without depending on a live external
//! service. Each stub exposes:
//!
//! 1. [`StubProvider::start`] — spin the service up. The constructor of
//!    each concrete stub plays this role (e.g. [`SqlStub::start`]); the
//!    trait method just hands back the kind for type-erased
//!    introspection.
//! 2. [`StubProvider::endpoint`] — the connection string the harness
//!    should use (a SQLite DB path, `http://127.0.0.1:port`, a
//!    filesystem root, etc.).
//! 3. [`StubProvider::drain_events`] — read every event observed since
//!    the last drain. The oracle's
//!    [`crate::dynamic::oracle::ProbePredicate::StubEventMatches`]
//!    walks these to decide whether a stub-observed effect satisfies
//!    a payload's predicate set.
//! 4. `Drop` — tear the service down. The runner relies on the
//!    `Arc<dyn StubProvider>` drop to release the listening socket /
//!    delete the temp filesystem root.
//!
//! # Lifecycle
//!
//! [`StubHarness::start`] spawns exactly the stubs in `kinds` (it does
//! *not* spawn the full set — the performance invariant is that a
//! harness with `stubs_required: []` boots in under 500 ms, so a
//! verifier that needs no stubs touches none of this module). The
//! harness keeps the stubs alive for the duration of a verify run and
//! drops them on scope exit; the runner does not have to know about
//! individual stub types.
//!
//! # Wiring
//!
//! - [`crate::dynamic::spec::HarnessSpec::stubs_required`] is populated
//!   at spec-derivation time from [`StubKind::for_cap`]; a SQL sink
//!   pulls in [`StubKind::Sql`], an SSRF sink pulls in
//!   [`StubKind::Http`], a path-traversal sink pulls in
//!   [`StubKind::Filesystem`]. Stubs whose presence is purely
//!   opportunistic (e.g. [`StubKind::Redis`]) are not auto-derived from
//!   any cap and must be added explicitly by a caller that knows it
//!   needs them.
//! - [`crate::dynamic::verify::verify_finding`] starts the required
//!   stubs *after* spec derivation and *before* spawning the sandbox,
//!   then injects each stub's endpoint into the sandbox env via the
//!   well-known [`StubKind::env_var`] name.
//! - Stub events are drained per-payload by the verifier (after each
//!   sandbox run) and passed into
//!   [`crate::dynamic::oracle::oracle_fired_with_stubs`] so the
//!   `StubEventMatches` predicate can satisfy a payload.

pub mod broker_kafka;
pub mod broker_nats;
pub mod broker_pubsub;
pub mod broker_rabbit;
pub mod broker_sqs;
pub mod filesystem;
pub mod http;
pub mod ldap_ber;
pub mod ldap_server;
pub mod mocks;
pub mod redis;
pub mod sql;
pub mod xpath_document;

pub use broker_kafka::{KAFKA_PUBLISH_MARKER, kafka_source};
pub use broker_nats::{NATS_PUBLISH_MARKER, nats_source};
pub use broker_pubsub::{PUBSUB_PUBLISH_MARKER, pubsub_source};
pub use broker_rabbit::{RABBIT_PUBLISH_MARKER, rabbit_source};
pub use broker_sqs::{SQS_PUBLISH_MARKER, sqs_source};
pub use filesystem::FilesystemStub;
pub use http::HttpStub;
pub use ldap_server::LdapStub;
pub use mocks::{MockKind, mock_source};
pub use redis::RedisStub;
pub use sql::SqlStub;

use crate::labels::Cap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

/// Which kind of stub a sink needs to fire under test.
///
/// Stored on [`crate::dynamic::spec::HarnessSpec::stubs_required`] as a
/// `Vec<StubKind>` so the spec serialises stably across versions even
/// when new stub kinds land in a future phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StubKind {
    /// In-memory SQLite-backed SQL stub. Endpoint is a DB file path.
    Sql,
    /// Localhost HTTP listener. Endpoint is `http://127.0.0.1:{port}`.
    Http,
    /// Minimal RESP-speaking Redis stub. Endpoint is `127.0.0.1:{port}`.
    Redis,
    /// Sandbox-local fake filesystem root. Endpoint is an absolute
    /// directory path that the harness is expected to use as its root.
    Filesystem,
    /// Minimal in-sandbox LDAP server stub (Phase 06 — Track J.4).
    /// Endpoint is `127.0.0.1:{port}`; the wire protocol is the text
    /// one-liner documented in
    /// [`crate::dynamic::stubs::ldap_server`].
    Ldap,
}

impl StubKind {
    /// Env-var name the verifier sets on the sandbox process to hand
    /// the stub's endpoint to the harness. Stable: harnesses read these
    /// names directly; bumping requires a coordinated lang-emitter
    /// update.
    pub const fn env_var(self) -> &'static str {
        match self {
            StubKind::Sql => "NYX_SQL_ENDPOINT",
            StubKind::Http => "NYX_HTTP_ENDPOINT",
            StubKind::Redis => "NYX_REDIS_ENDPOINT",
            StubKind::Filesystem => "NYX_FS_ROOT",
            StubKind::Ldap => ldap_server::LDAP_ENDPOINT_ENV_VAR,
        }
    }

    /// Stable string tag used in [`StubEvent::kind`] serialisation and
    /// the oracle's `StubEventMatches` predicate. Lower-case, stable
    /// across versions.
    pub const fn tag(self) -> &'static str {
        match self {
            StubKind::Sql => "sql",
            StubKind::Http => "http",
            StubKind::Redis => "redis",
            StubKind::Filesystem => "filesystem",
            StubKind::Ldap => "ldap",
        }
    }

    /// Derive the set of stubs a payload targeting `cap` needs spawned.
    ///
    /// The mapping is deliberately conservative: only caps whose sinks
    /// *cannot* fire in-process without a real boundary auto-derive a
    /// stub. Caps like `Cap::CODE_EXEC` or `Cap::FMT_STRING` execute
    /// purely inside the harness process and need no stub.
    pub fn for_cap(cap: Cap) -> Vec<StubKind> {
        let mut out = Vec::new();
        if cap.contains(Cap::SQL_QUERY) {
            out.push(StubKind::Sql);
        }
        if cap.contains(Cap::SSRF) || cap.contains(Cap::HEADER_INJECTION) {
            out.push(StubKind::Http);
        }
        if cap.contains(Cap::FILE_IO) {
            out.push(StubKind::Filesystem);
        }
        if cap.contains(Cap::LDAP_INJECTION) {
            out.push(StubKind::Ldap);
        }
        out
    }
}

/// One observation captured by a stub.
///
/// The contents are deliberately type-erased onto strings so all four
/// stub kinds share a single event schema. The `detail` map carries
/// per-kind structured fields (e.g. `method`/`path` for HTTP,
/// `command`/`args` for Redis) that an oracle predicate can dig into
/// without forking the schema by kind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StubEvent {
    /// Which stub recorded the event.
    pub kind: StubKind,
    /// Monotonic-ish nanosecond timestamp at capture time. Ordering
    /// across stubs is best-effort; absolute value is meaningless.
    pub captured_at_ns: u64,
    /// One-line human-readable summary. For SQL this is the executed
    /// query; for HTTP, the request line; for Redis, the command +
    /// args; for filesystem, the absolute path + op kind.
    pub summary: String,
    /// Per-kind structured fields. Empty when the stub captured only a
    /// summary.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub detail: BTreeMap<String, String>,
}

impl StubEvent {
    /// Construct a `StubEvent` stamped with the current monotonic
    /// timestamp. Tests pin `captured_at_ns` explicitly for
    /// determinism; production stubs use this constructor.
    pub fn new(kind: StubKind, summary: impl Into<String>) -> Self {
        Self {
            kind,
            captured_at_ns: monotonic_ns(),
            summary: summary.into(),
            detail: BTreeMap::new(),
        }
    }

    /// Attach a `detail` field, builder-style.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.detail.insert(key.into(), value.into());
        self
    }
}

/// Common operations on a running stub.
///
/// The trait is intentionally minimal so a future stub kind (e.g.
/// gRPC, Kafka) plugs in without touching the runner or the oracle.
pub trait StubProvider: Send + Sync + std::fmt::Debug {
    /// Discriminator for type-erased dispatch.
    fn kind(&self) -> StubKind;

    /// Connection string handed to the harness via
    /// [`StubKind::env_var`].
    fn endpoint(&self) -> String;

    /// Drain every event observed since the last drain. Always returns
    /// the events in insertion order; on a poisoned mutex returns an
    /// empty vec (the oracle treats "no events" as "stub was not
    /// touched").
    fn drain_events(&self) -> Vec<StubEvent>;

    /// Optional companion env var that publishes a host-visible
    /// recording-path the harness can append observations to.  The
    /// primary [`StubProvider::endpoint`] is the *connection* the
    /// harness uses (e.g. a SQLite DB path); the recording endpoint is
    /// the *side channel* a per-language shim helper writes structured
    /// records into so the host can correlate them on
    /// [`StubProvider::drain_events`].  Default `None` means the stub
    /// does not need a side-channel recording path.
    fn recording_endpoint(&self) -> Option<(&'static str, String)> {
        None
    }
}

/// Aggregate handle the verifier owns for the lifetime of one
/// `verify_finding` call.
///
/// Holds an `Arc<dyn StubProvider>` per requested kind so individual
/// stubs are dropped exactly when the harness goes out of scope. The
/// runner threads `StubHarness::endpoints()` into the sandbox env and
/// calls [`StubHarness::drain_all`] after each payload run.
#[derive(Debug, Default)]
pub struct StubHarness {
    stubs: Vec<Arc<dyn StubProvider>>,
}

impl StubHarness {
    /// Start the stubs in `kinds`. Each stub roots itself under
    /// `workdir` when it needs disk-backed state (SqlStub's DB file,
    /// FilesystemStub's fake root); network stubs ignore `workdir` and
    /// bind a random loopback port.
    ///
    /// Returns the first I/O error any stub raises during start. A
    /// partial start is *not* exposed: stubs that started before the
    /// failing one are dropped immediately so callers cannot observe
    /// a half-spawned harness.
    pub fn start(kinds: &[StubKind], workdir: &Path) -> std::io::Result<Self> {
        let mut stubs: Vec<Arc<dyn StubProvider>> = Vec::with_capacity(kinds.len());
        // Deduplicate kinds so repeated entries in spec.stubs_required
        // (e.g. cap = SQL_QUERY | SSRF | SQL_QUERY) don't double-spawn.
        let mut seen = Vec::with_capacity(kinds.len());
        for &k in kinds {
            if seen.contains(&k) {
                continue;
            }
            seen.push(k);
            let stub: Arc<dyn StubProvider> = match k {
                StubKind::Sql => Arc::new(SqlStub::start(workdir)?),
                StubKind::Http => Arc::new(HttpStub::start(workdir)?),
                StubKind::Redis => Arc::new(RedisStub::start()?),
                StubKind::Filesystem => Arc::new(FilesystemStub::start(workdir)?),
                StubKind::Ldap => Arc::new(LdapStub::start()?),
            };
            stubs.push(stub);
        }
        Ok(Self { stubs })
    }

    /// `(env_var_name, endpoint_value)` pairs the verifier merges into
    /// the sandbox env. The order matches `StubHarness::start`'s kinds
    /// argument so later entries override earlier ones if a harness is
    /// re-used with conflicting requests (it currently never is).
    ///
    /// Each stub publishes its primary connection endpoint
    /// ([`StubKind::env_var`]) first, then any companion recording
    /// endpoint ([`StubProvider::recording_endpoint`]) it owns.  Today
    /// only [`SqlStub`] publishes a recording endpoint
    /// (`NYX_SQL_LOG`); the other three stubs keep their primary
    /// endpoint as the sole pair.
    pub fn endpoints(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::with_capacity(self.stubs.len() * 2);
        for s in &self.stubs {
            out.push((s.kind().env_var(), s.endpoint()));
            if let Some(pair) = s.recording_endpoint() {
                out.push(pair);
            }
        }
        out
    }

    /// Borrow the underlying stub list (for tests and oracle wiring).
    pub fn stubs(&self) -> &[Arc<dyn StubProvider>] {
        &self.stubs
    }

    /// Drain events from every stub, tagging each with the stub kind.
    /// Returned in stub-spawn order; within a stub, events keep
    /// insertion order.
    pub fn drain_all(&self) -> Vec<StubEvent> {
        let mut all = Vec::new();
        for s in &self.stubs {
            all.extend(s.drain_events());
        }
        all
    }

    /// True when no stubs were spawned. The 500 ms boot budget in
    /// Phase 10's acceptance criteria covers exactly this case.
    pub fn is_empty(&self) -> bool {
        self.stubs.is_empty()
    }

    /// Number of spawned stubs (test helper).
    pub fn len(&self) -> usize {
        self.stubs.len()
    }
}

/// Monotonic-ish nanoseconds since boot. Used to timestamp `StubEvent`s
/// so a per-stub event log keeps insertion order even when multiple
/// stubs interleave writes.
pub(crate) fn monotonic_ns() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = *ORIGIN.get_or_init(Instant::now);
    origin.elapsed().as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn stub_kind_env_vars_are_distinct() {
        let names: Vec<&str> = [
            StubKind::Sql,
            StubKind::Http,
            StubKind::Redis,
            StubKind::Filesystem,
        ]
        .iter()
        .map(|k| k.env_var())
        .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "env vars must be unique");
    }

    #[test]
    fn for_cap_sql_query_picks_sql() {
        assert_eq!(StubKind::for_cap(Cap::SQL_QUERY), vec![StubKind::Sql]);
    }

    #[test]
    fn for_cap_ssrf_picks_http() {
        assert_eq!(StubKind::for_cap(Cap::SSRF), vec![StubKind::Http]);
    }

    #[test]
    fn for_cap_file_io_picks_filesystem() {
        assert_eq!(StubKind::for_cap(Cap::FILE_IO), vec![StubKind::Filesystem]);
    }

    #[test]
    fn for_cap_unrelated_cap_picks_nothing() {
        assert!(StubKind::for_cap(Cap::CODE_EXEC).is_empty());
    }

    #[test]
    fn for_cap_unions_multi_bit_caps() {
        let caps = Cap::SQL_QUERY | Cap::SSRF;
        let stubs = StubKind::for_cap(caps);
        assert!(stubs.contains(&StubKind::Sql));
        assert!(stubs.contains(&StubKind::Http));
        assert_eq!(stubs.len(), 2);
    }

    #[test]
    fn empty_kinds_starts_in_under_500ms() {
        // The "harness with `stubs_required: []` boots in under 500ms"
        // acceptance bullet specifically targets this case — when no
        // stubs are requested, StubHarness::start must be a no-op.
        let dir = TempDir::new().unwrap();
        let start = std::time::Instant::now();
        let h = StubHarness::start(&[], dir.path()).unwrap();
        let elapsed = start.elapsed();
        assert!(h.is_empty(), "empty kinds must spawn nothing");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "empty stubs_required must boot in <500ms (was {elapsed:?})"
        );
    }

    #[test]
    fn dedup_repeated_kinds_during_start() {
        let dir = TempDir::new().unwrap();
        let h =
            StubHarness::start(&[StubKind::Sql, StubKind::Sql, StubKind::Sql], dir.path()).unwrap();
        assert_eq!(h.len(), 1, "repeated kinds must be deduped");
    }

    #[test]
    fn endpoints_carries_stub_specific_env_var_names() {
        let dir = TempDir::new().unwrap();
        let h = StubHarness::start(
            &[StubKind::Sql, StubKind::Http, StubKind::Filesystem],
            dir.path(),
        )
        .unwrap();
        let names: Vec<&str> = h.endpoints().iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"NYX_SQL_ENDPOINT"));
        assert!(names.contains(&"NYX_HTTP_ENDPOINT"));
        assert!(names.contains(&"NYX_FS_ROOT"));
    }

    #[test]
    fn endpoints_includes_sql_recording_path_companion_var() {
        let dir = TempDir::new().unwrap();
        let h = StubHarness::start(&[StubKind::Sql], dir.path()).unwrap();
        let pairs = h.endpoints();
        let names: Vec<&str> = pairs.iter().map(|(n, _)| *n).collect();
        assert!(
            names.contains(&"NYX_SQL_ENDPOINT"),
            "primary endpoint must be present"
        );
        assert!(
            names.contains(&"NYX_SQL_LOG"),
            "SqlStub recording-path companion env var must be published"
        );
        let log_pair = pairs
            .iter()
            .find(|(n, _)| *n == "NYX_SQL_LOG")
            .expect("NYX_SQL_LOG entry");
        assert!(
            log_pair.1.ends_with("nyx_sql_stub.queries.log"),
            "recording path must point at the queries log file, got {}",
            log_pair.1
        );
    }
}
