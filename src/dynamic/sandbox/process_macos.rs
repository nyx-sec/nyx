//! Phase 18 (Track E.2) — macOS process backend hardening.
//!
//! macOS analogue of [`super::process_linux`].  Where the Linux backend
//! installs a `pre_exec` sequence (prctl + rlimits + unshare + chroot +
//! seccomp-bpf), the macOS backend wraps the harness command with
//! `sandbox-exec(1)` driven by a per-capability `.sb` policy file.
//!
//! Profile selection
//! -----------------
//! [`profile_for_caps`] maps the [`SandboxOptions::seccomp_caps`] bitset
//! (set by the verifier from `spec.expected_cap`) to a profile name in
//! `src/dynamic/sandbox_profiles/`:
//!
//! | Cap bit          | Profile          |
//! | ---------------- | ---------------- |
//! | `FILE_IO`        | `path_traversal` |
//! | `SSRF`           | `ssrf`           |
//! | `CODE_EXEC`      | `cmdi`           |
//! | `DESERIALIZE`    | `deserialize`    |
//! | everything else  | `base`           |
//!
//! Profiles are baked into the binary via `include_str!` and materialised
//! into a per-process tempdir on first use so `sandbox-exec -f` can read
//! them.
//!
//! Fallback
//! --------
//! `sandbox-exec` is shipped on every supported macOS release but the
//! binary path can be missing in stripped CI images.  When
//! [`sandbox_exec_available`] returns `false`, the wrapper is a no-op
//! and [`wrap_plan`] tags the run as [`HardeningLevel::Trusted`] on the
//! returned [`WrapResult`] — the verifier reads this back via
//! `VerifyOptions::refuse_filesystem_confirm` and downgrades filesystem-
//! oracle verdicts to
//! [`crate::evidence::InconclusiveReason::BackendInsufficient`].
//!
//! Tests
//! -----
//! See `tests/sandbox_hardening_macos.rs` for the per-primitive
//! acceptance suite; `cfg(target_os = "macos")` gates every test so the
//! Linux CI row sees only the skip placeholder.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

// ── HardeningOutcome flow ─────────────────────────────────────────────────────
//
// Phase 18 originally recorded the outcome to a process-global
// `LAST_OUTCOME` singleton.  Phase 17/18 sweep dropped that singleton
// because `verify_finding` runs under `rayon::par_iter` in `scan.rs`, so
// concurrent wraps would overwrite each other.  [`wrap_plan`] now
// returns the outcome via [`WrapResult`] and `run_process` stashes it on
// the returned `SandboxOutcome`.

// ── HardeningLevel reporting ─────────────────────────────────────────────────

/// Coarse summary of the macOS sandbox-exec wrap outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningLevel {
    /// `sandbox-exec` was unavailable on the host — the harness ran
    /// unconfined.  The verifier translates this into
    /// `refuse_filesystem_confirm = true` so filesystem-escape oracles
    /// degrade to `Inconclusive(BackendInsufficient)` rather than
    /// silently returning `Confirmed` against an unhardened backend.
    Trusted,
    /// The harness was wrapped with `sandbox-exec -f <profile>` and the
    /// profile selected matched [`profile_for_caps`].
    Sandboxed,
    /// `sandbox-exec` was available but the spawn returned a non-zero
    /// status before the harness could run.  Same downgrade as
    /// [`HardeningLevel::Trusted`] from the verifier's point of view.
    Failed,
}

/// Per-run summary returned by [`wrap_plan`].  Threaded back to the
/// caller through [`WrapResult`] so `run_process` can stash it on the
/// [`crate::dynamic::sandbox::SandboxOutcome`] for the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardeningOutcome {
    pub level: HardeningLevel,
    /// Name of the matched profile (e.g. `"path_traversal"`).  Empty
    /// string when [`HardeningLevel::Trusted`].
    pub profile: String,
}

// ── sandbox-exec availability + binary path ──────────────────────────────────

/// Env override consulted by [`sandbox_exec_bin`]; tests set this to
/// `"/nonexistent/sandbox-exec"` to force the unavailable branch.
pub const SANDBOX_EXEC_BIN_ENV: &str = "NYX_SANDBOX_EXEC_BIN";

/// Resolve the `sandbox-exec` binary path.  Honours
/// [`SANDBOX_EXEC_BIN_ENV`] so tests can simulate a missing binary
/// without touching `/usr/bin/sandbox-exec`.
pub fn sandbox_exec_bin() -> PathBuf {
    if let Ok(p) = std::env::var(SANDBOX_EXEC_BIN_ENV) {
        return PathBuf::from(p);
    }
    PathBuf::from("/usr/bin/sandbox-exec")
}

/// `true` when [`sandbox_exec_bin`] points at an executable regular
/// file.  Result is *not* cached across calls so the
/// [`SANDBOX_EXEC_BIN_ENV`] override can be flipped per-test.
pub fn sandbox_exec_available() -> bool {
    let bin = sandbox_exec_bin();
    match std::fs::metadata(&bin) {
        Ok(m) => m.is_file(),
        Err(_) => false,
    }
}

// ── Profile selection + materialisation ──────────────────────────────────────

/// Baked-in `.sb` source.  Each entry is the contents of one file under
/// `src/dynamic/sandbox_profiles/`; the runtime materialises them into a
/// per-process tempdir on first use.
const PROFILE_SOURCES: &[(&str, &str)] = &[
    ("base", include_str!("../sandbox_profiles/base.sb")),
    ("cmdi", include_str!("../sandbox_profiles/cmdi.sb")),
    (
        "path_traversal",
        include_str!("../sandbox_profiles/path_traversal.sb"),
    ),
    ("ssrf", include_str!("../sandbox_profiles/ssrf.sb")),
    ("deserialize", include_str!("../sandbox_profiles/deserialize.sb")),
    ("xxe", include_str!("../sandbox_profiles/xxe.sb")),
];

/// Cap → profile-name dispatch.  The most restrictive matching profile
/// wins: filesystem caps outrank network caps outrank CODE_EXEC outranks
/// DESERIALIZE outranks XXE.  Filesystem-shaped caps (`FILE_IO`,
/// `SQL_QUERY` — DBs are files in WORKDIR) map to `path_traversal`;
/// outbound-network-shaped caps (`SSRF`, `HEADER_INJECTION`,
/// `OPEN_REDIRECT`, `UNVALIDATED_REDIRECT`, `LDAP_INJECTION`,
/// `XPATH_INJECTION`) map to `ssrf` since they share the "outbound
/// allowed; host secrets denied" shape.  `XXE` maps to its own profile
/// which denies non-loopback outbound (entity fetch) on top of the
/// shared secret-file denylist.  Remaining caps with no shared shape
/// (CRYPTO, AUTH, RACE, MEMORY_SAFETY, XSS) fall back to `base` because
/// they are code-path bugs rather than sandbox-boundary sinks.
pub fn profile_for_caps(caps: u32) -> &'static str {
    // Mirror the bit positions declared in `src/labels/mod.rs`.
    const FILE_IO: u32 = 1 << 5;
    const SQL_QUERY: u32 = 1 << 7;
    const DESERIALIZE: u32 = 1 << 8;
    const SSRF: u32 = 1 << 9;
    const CODE_EXEC: u32 = 1 << 10;
    const LDAP_INJECTION: u32 = 1 << 14;
    const XPATH_INJECTION: u32 = 1 << 15;
    const HEADER_INJECTION: u32 = 1 << 16;
    const OPEN_REDIRECT: u32 = 1 << 17;
    const UNVALIDATED_REDIRECT: u32 = 1 << 18;
    const XXE: u32 = 1 << 19;

    const FS_SHAPED: u32 = FILE_IO | SQL_QUERY;
    const NET_SHAPED: u32 =
        SSRF | LDAP_INJECTION | XPATH_INJECTION | HEADER_INJECTION | OPEN_REDIRECT | UNVALIDATED_REDIRECT;

    if caps & FS_SHAPED != 0 {
        "path_traversal"
    } else if caps & NET_SHAPED != 0 {
        "ssrf"
    } else if caps & CODE_EXEC != 0 {
        "cmdi"
    } else if caps & DESERIALIZE != 0 {
        "deserialize"
    } else if caps & XXE != 0 {
        "xxe"
    } else {
        "base"
    }
}

/// Lazy materialised tempdir holding the `.sb` files unpacked from the
/// binary.  Survives for the lifetime of the process — the system's
/// `tmp` reaper sweeps the dir on next boot.
static PROFILE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static PROFILE_PATHS: OnceLock<Mutex<BTreeMap<&'static str, PathBuf>>> = OnceLock::new();

fn profile_dir() -> Option<&'static Path> {
    PROFILE_DIR
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("nyx-sandbox-profiles");
            std::fs::create_dir_all(&dir).ok()?;
            Some(dir)
        })
        .as_deref()
}

fn profile_paths() -> &'static Mutex<BTreeMap<&'static str, PathBuf>> {
    PROFILE_PATHS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Return the absolute path of the named profile, writing the
/// `include_str!`-baked source to the per-process tempdir on first
/// access.  Returns `None` when the profile name is unknown or the
/// tempdir could not be created / written.
pub fn profile_path(name: &str) -> Option<PathBuf> {
    // Resolve the static source first so we hold a `&'static str` key.
    let (key, source) = PROFILE_SOURCES.iter().find(|(k, _)| *k == name)?;
    {
        let cache = profile_paths().lock().ok()?;
        if let Some(p) = cache.get(key) {
            return Some(p.clone());
        }
    }
    let dir = profile_dir()?;
    let path = dir.join(format!("{key}.sb"));
    // Always overwrite on first miss in this process so an upgraded nyx
    // binary picks up new profile content even when a previous version
    // left a stale `.sb` file under `std::env::temp_dir()`.  The in-process
    // `PROFILE_PATHS` cache then short-circuits subsequent lookups so the
    // write happens at most once per profile per process lifetime.
    let body: String = match deny_default_seed_for(key) {
        Some(seed) => splice_deny_default(source, &seed),
        None => source.to_string(),
    };
    std::fs::write(&path, &body).ok()?;
    let mut cache = profile_paths().lock().ok()?;
    cache.insert(*key, path.clone());
    Some(path)
}

// ── deny-default splice (Phase 18 follow-up) ─────────────────────────────────
//
// The default profile bodies ship with `(allow default)` because the
// trace-driven enumeration of the per-cap allowlist seed has not been
// authored yet.  This block carries the pure splice helper + the env-
// var-gated seed lookup so the corpus-walking half (Phase 18 follow-up
// path (a)) only has to drop a file under `tools/sb-trace/{cap}.allow`
// and set `NYX_SB_DENY_DEFAULT=1` to flip the materialised profile to
// `(deny default)` + the seeded allowlist.  The splice is pure (string
// in, string out) so it is tested against synthetic seeds in this file
// without needing macOS-host sandbox-exec access.

/// Env var consulted by [`profile_path`] to enable the deny-default
/// splice.  When set to `1` / `true`, [`deny_default_seed_for`] is
/// invoked for every materialised profile; missing seeds fall back to
/// the baked `(allow default)` body so misconfiguration cannot brick
/// the sandbox-exec backend.
pub const SB_DENY_DEFAULT_ENV: &str = "NYX_SB_DENY_DEFAULT";

/// Env var consulted by [`deny_default_seed_for`] to locate the seed
/// directory.  Defaults to `tools/sb-trace/` relative to the workspace
/// root when unset; tests override this to point at a tempdir-backed
/// fixture set.
pub const SB_SEED_DIR_ENV: &str = "NYX_SB_SEED_DIR";

/// Return the deny-default seed body for the named cap profile when
/// the env-var opt-in is set and a seed file is on disk.  Returns
/// `None` when the env var is unset, the seed dir is missing, or the
/// specific cap's seed file does not exist.  The seed is a free-form
/// `.sb` fragment (allow directives + comments) that gets appended
/// verbatim after the `(deny default)` rewrite.
fn deny_default_seed_for(cap: &str) -> Option<String> {
    let flag = std::env::var(SB_DENY_DEFAULT_ENV).ok()?;
    if !matches!(flag.as_str(), "1" | "true" | "TRUE" | "yes" | "YES") {
        return None;
    }
    let seed_dir = std::env::var(SB_SEED_DIR_ENV)
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tools/sb-trace"));
    let seed_path = seed_dir.join(format!("{cap}.allow"));
    std::fs::read_to_string(&seed_path).ok()
}

/// Rewrite a profile body from `(allow default)` to `(deny default)`,
/// appending the seed contents as additional allow directives.  Pure
/// function — easy to test without macOS-host sandbox-exec access.
///
/// The splice strategy is conservative:
///
/// 1. Replace the first occurrence of `(allow default)` with
///    `(deny default)`.  If none is present, the body is appended to
///    as-is (callers should not invoke the splice on a profile that
///    already runs deny-default).
/// 2. Append a banner line + the seed body so the deny-default
///    rewrite is visually obvious in the materialised file.
///
/// `sandbox-exec` profile language resolves directives in textual
/// order with later matches winning, so the appended seed allows
/// stack cleanly on top of the `(deny default)` base.
pub fn splice_deny_default(source: &str, seed: &str) -> String {
    let needle = "(allow default)";
    let mut rewritten = if source.contains(needle) {
        source.replacen(needle, "(deny default)", 1)
    } else {
        source.to_string()
    };
    if !rewritten.ends_with('\n') {
        rewritten.push('\n');
    }
    rewritten.push('\n');
    rewritten.push_str(
        ";; ── deny-default seed (spliced by NYX_SB_DENY_DEFAULT=1) ──────────\n",
    );
    rewritten.push_str(seed.trim_end());
    rewritten.push('\n');
    rewritten
}

/// Drop the in-process [`PROFILE_PATHS`] cache.  Intended for
/// integration tests that flip `NYX_SB_DENY_DEFAULT` mid-process and
/// need the next [`profile_path`] call to re-run the splice path
/// instead of returning a previously materialised entry.  Hidden from
/// the rendered API surface; production code does not touch the cache.
#[doc(hidden)]
pub fn clear_profile_path_cache_for_tests() {
    if let Ok(mut cache) = profile_paths().lock() {
        cache.clear();
    }
}

// ── Command wrapping ─────────────────────────────────────────────────────────

/// Inputs to [`wrap_plan`] — the original harness command split into
/// resolved-path + argv-tail form.  The caller is expected to have
/// already resolved `cmd_path` via `find_in_host_path` so the wrapped
/// `sandbox-exec` invocation receives an absolute target binary.
pub struct WrapInput<'a> {
    pub cmd_path: &'a Path,
    pub cmd_args: &'a [String],
    pub workdir: &'a Path,
    pub caps: u32,
    pub profile_override: Option<&'a str>,
}

/// Outputs of [`wrap_plan`] when sandbox-exec wrapping is in effect.
/// `binary` is the `sandbox-exec` path (or the env-override) and `args`
/// is the full argv (excluding `argv[0]`).
pub struct WrapPlan {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub profile: &'static str,
}

/// Result of [`wrap_plan`].  Always carries a [`HardeningOutcome`] so
/// the caller can stash it on the `SandboxOutcome` even when wrapping
/// itself was a no-op (`plan = None` + `outcome.level = Trusted`).
pub struct WrapResult {
    /// Wrap plan when `sandbox-exec` was applied; `None` when the
    /// harness should run unwrapped.  The verifier's
    /// `refuse_filesystem_confirm` flag keeps the verdict honest in the
    /// `None` case.
    pub plan: Option<WrapPlan>,
    pub outcome: HardeningOutcome,
}

/// Build the `sandbox-exec -f <profile> -D WORKDIR=<workdir> -- <cmd>`
/// argv for `cmd_path + cmd_args`.  The returned [`WrapResult`]
/// `plan` is `None` when:
///
/// - `sandbox-exec` is not on the host (`outcome.level = Trusted`),
/// - the profile name is unknown (`outcome.level = Trusted`), or
/// - the profile file could not be materialised in `/tmp`
///   (`outcome.level = Failed`).
pub fn wrap_plan(input: &WrapInput<'_>) -> WrapResult {
    if !sandbox_exec_available() {
        return WrapResult {
            plan: None,
            outcome: HardeningOutcome {
                level: HardeningLevel::Trusted,
                profile: String::new(),
            },
        };
    }
    let profile = input.profile_override.unwrap_or_else(|| profile_for_caps(input.caps));
    // Profile keys must be `&'static str` (from `PROFILE_SOURCES`); reject
    // unknown overrides up-front so we don't accidentally wrap with a
    // profile we have no source for.
    let resolved_key = PROFILE_SOURCES
        .iter()
        .find(|(k, _)| *k == profile)
        .map(|(k, _)| *k);
    let resolved_key = match resolved_key {
        Some(k) => k,
        None => {
            return WrapResult {
                plan: None,
                outcome: HardeningOutcome {
                    level: HardeningLevel::Trusted,
                    profile: String::new(),
                },
            };
        }
    };
    let profile_file = match profile_path(resolved_key) {
        Some(p) => p,
        None => {
            return WrapResult {
                plan: None,
                outcome: HardeningOutcome {
                    level: HardeningLevel::Failed,
                    profile: resolved_key.to_owned(),
                },
            };
        }
    };

    let workdir_abs = std::fs::canonicalize(input.workdir).unwrap_or_else(|_| input.workdir.to_path_buf());

    let mut args: Vec<String> = Vec::with_capacity(6 + input.cmd_args.len());
    args.push("-f".to_owned());
    args.push(profile_file.to_string_lossy().into_owned());
    args.push("-D".to_owned());
    args.push(format!("WORKDIR={}", workdir_abs.to_string_lossy()));
    args.push(input.cmd_path.to_string_lossy().into_owned());
    for a in input.cmd_args {
        args.push(a.clone());
    }

    WrapResult {
        plan: Some(WrapPlan {
            binary: sandbox_exec_bin(),
            args,
            profile: resolved_key,
        }),
        outcome: HardeningOutcome {
            level: HardeningLevel::Sandboxed,
            profile: resolved_key.to_owned(),
        },
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_for_caps_prefers_file_io() {
        const FILE_IO: u32 = 1 << 5;
        const SSRF: u32 = 1 << 9;
        const CODE_EXEC: u32 = 1 << 10;
        assert_eq!(profile_for_caps(FILE_IO), "path_traversal");
        assert_eq!(profile_for_caps(FILE_IO | SSRF), "path_traversal");
        assert_eq!(profile_for_caps(SSRF | CODE_EXEC), "ssrf");
        assert_eq!(profile_for_caps(CODE_EXEC), "cmdi");
        assert_eq!(profile_for_caps(0), "base");
    }

    #[test]
    fn profile_for_caps_routes_filesystem_shaped_caps_to_path_traversal() {
        // SQL_QUERY shares the `file-write into WORKDIR / file-read of
        // host secrets denied` shape with FILE_IO (SQLite DBs live as
        // files in the workdir), so it routes to the same profile.
        const SQL_QUERY: u32 = 1 << 7;
        const CODE_EXEC: u32 = 1 << 10;
        assert_eq!(profile_for_caps(SQL_QUERY), "path_traversal");
        // Filesystem shape outranks the lesser-restrictive cmdi profile.
        assert_eq!(profile_for_caps(SQL_QUERY | CODE_EXEC), "path_traversal");
    }

    #[test]
    fn profile_for_caps_routes_outbound_network_caps_to_ssrf() {
        // Outbound HTTP request sinks (HEADER_INJECTION / OPEN_REDIRECT /
        // UNVALIDATED_REDIRECT) and other network-traffic injection caps
        // (LDAP_INJECTION / XPATH_INJECTION) all share the SSRF shape:
        // outbound allowed, host-secret reads denied.
        const LDAP_INJECTION: u32 = 1 << 14;
        const XPATH_INJECTION: u32 = 1 << 15;
        const HEADER_INJECTION: u32 = 1 << 16;
        const OPEN_REDIRECT: u32 = 1 << 17;
        const UNVALIDATED_REDIRECT: u32 = 1 << 18;
        assert_eq!(profile_for_caps(LDAP_INJECTION), "ssrf");
        assert_eq!(profile_for_caps(XPATH_INJECTION), "ssrf");
        assert_eq!(profile_for_caps(HEADER_INJECTION), "ssrf");
        assert_eq!(profile_for_caps(OPEN_REDIRECT), "ssrf");
        assert_eq!(profile_for_caps(UNVALIDATED_REDIRECT), "ssrf");
    }

    #[test]
    fn profile_for_caps_falls_back_to_base_for_unmapped_caps() {
        // CRYPTO / AUTH / RACE / MEMORY_SAFETY / XSS are code-path bugs
        // without a sandbox-boundary kill path, so they fall back to the
        // baseline secret-file denylist.
        const CRYPTO: u32 = 1 << 11;
        const AUTH: u32 = 1 << 12;
        const RACE: u32 = 1 << 20;
        const MEMORY_SAFETY: u32 = 1 << 21;
        const XSS: u32 = 1 << 6;
        assert_eq!(profile_for_caps(CRYPTO), "base");
        assert_eq!(profile_for_caps(AUTH), "base");
        assert_eq!(profile_for_caps(RACE), "base");
        assert_eq!(profile_for_caps(MEMORY_SAFETY), "base");
        assert_eq!(profile_for_caps(XSS), "base");
    }

    #[test]
    fn profile_for_caps_routes_xxe_to_xxe_profile() {
        // XXE entity resolution kills via an outbound HTTP / DNS fetch
        // against an attacker-controlled SYSTEM URL.  The dedicated
        // profile denies non-loopback outbound so the entity fetch faults
        // before the parser hands the leaked data back.
        const XXE: u32 = 1 << 19;
        const DESERIALIZE: u32 = 1 << 8;
        assert_eq!(profile_for_caps(XXE), "xxe");
        // DESERIALIZE outranks XXE in the dispatch chain (gadget chains
        // commonly subsume entity-style payloads).
        assert_eq!(profile_for_caps(XXE | DESERIALIZE), "deserialize");
    }

    #[test]
    fn profile_path_materialises_xxe_profile_source() {
        let path = profile_path("xxe").expect("xxe profile");
        let contents = std::fs::read_to_string(&path).expect("read .sb");
        assert!(contents.contains("(version 1)"));
        assert!(contents.contains("(deny network-outbound)"));
        assert!(contents.contains("/etc/passwd"));
    }

    #[test]
    fn profile_path_materialises_baked_source() {
        let path = profile_path("base").expect("base profile");
        let contents = std::fs::read_to_string(&path).expect("read .sb");
        assert!(contents.contains("(version 1)"));
        assert!(contents.contains("/etc/passwd"));

        // The path_traversal profile substitutes WORKDIR at spawn time,
        // so its baked source contains the param reference.
        let trav = profile_path("path_traversal").expect("path_traversal profile");
        let trav_src = std::fs::read_to_string(&trav).expect("read .sb");
        assert!(trav_src.contains("(param \"WORKDIR\")"));
    }

    #[test]
    fn profile_path_unknown_name_is_none() {
        assert!(profile_path("does_not_exist").is_none());
    }

    #[test]
    fn sandbox_exec_bin_honours_env_override() {
        // SAFETY: tests are run serially with the macOS hardening suite;
        // resetting the env var below restores the default for subsequent
        // tests in the same process.
        unsafe { std::env::set_var(SANDBOX_EXEC_BIN_ENV, "/nonexistent/sandbox-exec") };
        assert_eq!(sandbox_exec_bin(), PathBuf::from("/nonexistent/sandbox-exec"));
        assert!(!sandbox_exec_available());
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
    }

    #[test]
    fn splice_deny_default_replaces_allow_default_and_appends_seed() {
        let source = "(version 1)\n(allow default)\n(deny file-read* (literal \"/etc/passwd\"))\n";
        let seed = "(allow file-read* (literal \"/opt/homebrew/lib/python3.11/lib-dynload\"))\n";
        let out = splice_deny_default(source, seed);
        assert!(out.contains("(deny default)"));
        assert!(!out.contains("(allow default)"));
        // Original deny rule survives.
        assert!(out.contains("(deny file-read* (literal \"/etc/passwd\"))"));
        // Seed appended verbatim.
        assert!(out.contains("/opt/homebrew/lib/python3.11/lib-dynload"));
        // Banner emitted exactly once so the deny-default rewrite is visually obvious.
        assert_eq!(out.matches(";; ── deny-default seed").count(), 1);
        // Order: (deny default) must precede the seed allows so the appended
        // allows can override the deny baseline (sandbox-exec resolves later
        // matches over earlier ones).
        let deny_pos = out.find("(deny default)").expect("deny default");
        let seed_pos = out.find("/opt/homebrew").expect("seed");
        assert!(deny_pos < seed_pos);
    }

    #[test]
    fn splice_deny_default_only_replaces_first_allow_default() {
        // A pathological profile with two `(allow default)` lines: only the
        // first should be rewritten so the second one becomes the
        // (effectively dead) override.  This shape never appears in tree
        // today, but the assertion locks the contract.
        let source = "(allow default)\n(deny file-write*)\n(allow default)\n";
        let seed = "(allow network-outbound (remote tcp \"127.0.0.1:*\"))\n";
        let out = splice_deny_default(source, seed);
        assert_eq!(out.matches("(deny default)").count(), 1);
        assert_eq!(out.matches("(allow default)").count(), 1);
    }

    #[test]
    fn splice_deny_default_handles_source_missing_allow_default() {
        // Profile already in deny-default form: splice just appends the
        // seed without touching the body.
        let source = "(version 1)\n(deny default)\n";
        let seed = "(allow file-read* (literal \"/usr/lib/dyld\"))\n";
        let out = splice_deny_default(source, seed);
        assert_eq!(out.matches("(deny default)").count(), 1);
        assert!(out.contains("/usr/lib/dyld"));
    }

    #[test]
    fn deny_default_seed_for_returns_none_without_env_opt_in() {
        // SAFETY: tests in this module mutate process-global env; the
        // macOS hardening integration suite serialises around the same
        // env vars so cargo nextest's per-test process isolation does not
        // help here.  Explicit unset before + after each test to keep the
        // body honest for sibling tests.
        unsafe { std::env::remove_var(SB_DENY_DEFAULT_ENV) };
        assert!(deny_default_seed_for("cmdi").is_none());
    }

    #[test]
    fn deny_default_seed_for_returns_some_when_env_set_and_seed_present() {
        let tmp = std::env::temp_dir().join("nyx-sb-seed-test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create seed tempdir");
        std::fs::write(
            tmp.join("cmdi.allow"),
            ";; synthetic seed for unit test\n(allow process-fork)\n",
        )
        .expect("write seed");
        unsafe {
            std::env::set_var(SB_DENY_DEFAULT_ENV, "1");
            std::env::set_var(SB_SEED_DIR_ENV, &tmp);
        }
        let seed = deny_default_seed_for("cmdi").expect("seed body");
        assert!(seed.contains("(allow process-fork)"));
        // Missing cap with the same env set still returns None.
        assert!(deny_default_seed_for("does_not_exist").is_none());
        unsafe {
            std::env::remove_var(SB_DENY_DEFAULT_ENV);
            std::env::remove_var(SB_SEED_DIR_ENV);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn wrap_plan_returns_none_when_sandbox_exec_missing() {
        unsafe { std::env::set_var(SANDBOX_EXEC_BIN_ENV, "/nonexistent/sandbox-exec") };
        let input = WrapInput {
            cmd_path: Path::new("/usr/bin/true"),
            cmd_args: &[],
            workdir: Path::new("/tmp"),
            caps: 0,
            profile_override: None,
        };
        let result = wrap_plan(&input);
        assert!(result.plan.is_none());
        assert_eq!(result.outcome.level, HardeningLevel::Trusted);
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn wrap_plan_returns_sandboxed_when_sandbox_exec_present() {
        // Skip when the host doesn't actually have /usr/bin/sandbox-exec
        // (e.g. someone reading SANDBOX_EXEC_BIN_ENV from a parent shell).
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        if !sandbox_exec_available() {
            eprintln!("SKIP: /usr/bin/sandbox-exec missing on this host");
            return;
        }
        let input = WrapInput {
            cmd_path: Path::new("/usr/bin/true"),
            cmd_args: &[],
            workdir: Path::new("/tmp"),
            caps: 1 << 5, // FILE_IO
            profile_override: None,
        };
        let result = wrap_plan(&input);
        let plan = result.plan.expect("plan");
        assert_eq!(plan.profile, "path_traversal");
        assert_eq!(plan.binary, PathBuf::from("/usr/bin/sandbox-exec"));
        assert!(plan.args.iter().any(|a| a == "-f"));
        assert!(plan.args.iter().any(|a| a.starts_with("WORKDIR=")));
        assert_eq!(result.outcome.level, HardeningLevel::Sandboxed);
        assert_eq!(result.outcome.profile, "path_traversal");
    }
}
