//! Prewarmed sandbox baseline directories (Track P.0).
//!
//! A harness needs the language toolchain's heavyweight dependency tree
//! (`node_modules`, `vendor`, `target/`, …) but that tree is identical across
//! every finding in a run — installing it per-finding is the bulk of the
//! per-workdir setup cost. A [`Baseline`] holds one shared, warmed copy under
//! the build-pool cache dir; each per-finding workdir gets a cheap snapshot of
//! it:
//!
//! - **macOS** — a `clonefile` CoW snapshot (via
//!   [`crate::dynamic::harness::copy_workdir`]).
//! - **Linux** — a read-only `mount --bind`, falling back to a reflink copy
//!   when bind mounts are unavailable (no `CAP_SYS_ADMIN` / not in a mount
//!   namespace).
//!
//! The baseline root honours `NYX_BUILD_POOL_DIR` through
//! [`crate::dynamic::build_pool::pool_cache_dir`], so tests can redirect it
//! into a `TempDir` and it shares the same on-disk layout as the Phase 22/23
//! build pools (`<cache>/dynamic/build-pool/<lang>/baseline`).

use crate::symbol::Lang;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Canonical pinned toolchain subdirectories per language.
///
/// These are the content-addressed dependency trees a harness needs but that
/// never change between findings, so they are warmed once in the shared
/// baseline and snapshotted into each per-finding workdir. Languages whose
/// harnesses carry no pinned tree (C / C++) return an empty slice.
pub fn pinned_subdirs(lang: Lang) -> &'static [&'static str] {
    match lang {
        Lang::JavaScript | Lang::TypeScript => &["node_modules"],
        Lang::Php => &["vendor"],
        Lang::Ruby => &["vendor/bundle"],
        Lang::Rust => &["target"],
        Lang::Go => &["go-pkg"],
        Lang::Python => &[".venv"],
        Lang::Java => &["lib"],
        Lang::C | Lang::Cpp => &[],
    }
}

/// Build-pool cache slug for `lang` — matches the Phase 22/23 pool layout so
/// the baseline lives next to its toolchain's pool caches.
fn lang_slug(lang: Lang) -> &'static str {
    match lang {
        Lang::JavaScript | Lang::TypeScript => "node",
        Lang::Python => "python",
        Lang::Php => "php",
        Lang::Ruby => "ruby",
        Lang::Go => "go",
        Lang::Rust => "rust",
        Lang::Java => "java",
        Lang::C => "c",
        Lang::Cpp => "cpp",
    }
}

/// A shared, prewarmed baseline directory for one language toolchain.
pub struct Baseline {
    lang: Lang,
    root: PathBuf,
}

impl Baseline {
    /// Locate (and create) the shared baseline root for `lang`.
    ///
    /// Returns `None` only when no cache dir is available (neither
    /// `NYX_BUILD_POOL_DIR` nor a platform cache dir) — callers then skip the
    /// baseline and stage the workdir the legacy way.
    pub fn ensure(lang: Lang) -> Option<Self> {
        let root = crate::dynamic::build_pool::pool_cache_dir(lang_slug(lang), "baseline")?;
        Some(Self { lang, root })
    }

    /// Root directory holding the warmed pinned subdirs.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// True when at least one pinned subdir is present and non-empty — i.e. a
    /// prior `prepare_*` build has warmed the baseline. A cold baseline makes
    /// [`Self::snapshot_into`] a no-op so the caller falls back to a normal
    /// per-workdir install.
    pub fn is_warm(&self) -> bool {
        pinned_subdirs(self.lang).iter().any(|sub| {
            let p = self.root.join(sub);
            p.is_dir()
                && fs::read_dir(&p)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
        })
    }

    /// Snapshot every warmed pinned subdir into `workdir`.
    ///
    /// macOS uses a `clonefile` CoW snapshot; Linux attempts a read-only
    /// `mount --bind` and falls back to a reflink copy when bind mounts are
    /// unavailable. Missing subdirs are skipped, so a partially warmed
    /// baseline still snapshots what it has.
    pub fn snapshot_into(&self, workdir: &Path) -> io::Result<()> {
        for sub in pinned_subdirs(self.lang) {
            let src = self.root.join(sub);
            if !src.is_dir() {
                continue;
            }
            let dst = workdir.join(sub);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)?;
            }
            #[cfg(target_os = "linux")]
            if bind_mount_ro(&src, &dst).is_ok() {
                continue;
            }
            crate::dynamic::harness::copy_workdir(&src, &dst)?;
        }
        Ok(())
    }
}

/// Read-only `mount --bind src dst` on Linux.
///
/// A bind mount cannot be made read-only in a single call: Linux applies the
/// `MS_RDONLY` flag only on a subsequent `MS_REMOUNT`. A failed remount leaves
/// the read-write bind in place (still far cheaper than a copy), so the harness
/// gets the dependency tree either way; the read-only guarantee is best-effort.
#[cfg(target_os = "linux")]
fn bind_mount_ro(src: &Path, dst: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    unsafe extern "C" {
        fn mount(
            src: *const core::ffi::c_char,
            target: *const core::ffi::c_char,
            fstype: *const core::ffi::c_char,
            flags: u64,
            data: *const core::ffi::c_void,
        ) -> i32;
    }

    const MS_RDONLY: u64 = 0x1;
    const MS_REMOUNT: u64 = 0x20;
    const MS_BIND: u64 = 0x1000;
    const MS_REC: u64 = 0x4000;

    fs::create_dir_all(dst)?;
    let csrc =
        CString::new(src.as_os_str().as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let cdst =
        CString::new(dst.as_os_str().as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let bind = unsafe {
        mount(
            csrc.as_ptr(),
            cdst.as_ptr(),
            std::ptr::null(),
            MS_BIND | MS_REC,
            std::ptr::null(),
        )
    };
    if bind != 0 {
        return Err(io::Error::last_os_error());
    }
    // Best-effort read-only remount; leave the rw bind if it fails.
    unsafe {
        mount(
            std::ptr::null(),
            cdst.as_ptr(),
            std::ptr::null(),
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC,
            std::ptr::null(),
        )
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct PoolDirGuard {
        _lock: MutexGuard<'static, ()>,
        prior: Option<String>,
    }

    impl PoolDirGuard {
        fn set(path: &Path) -> Self {
            let lock = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let prior = std::env::var("NYX_BUILD_POOL_DIR").ok();
            unsafe { std::env::set_var("NYX_BUILD_POOL_DIR", path) };
            Self { _lock: lock, prior }
        }
    }

    impl Drop for PoolDirGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => unsafe { std::env::set_var("NYX_BUILD_POOL_DIR", v) },
                None => unsafe { std::env::remove_var("NYX_BUILD_POOL_DIR") },
            }
        }
    }

    #[test]
    fn pinned_subdirs_cover_dependency_trees() {
        assert_eq!(pinned_subdirs(Lang::JavaScript), &["node_modules"]);
        assert_eq!(pinned_subdirs(Lang::Php), &["vendor"]);
        assert_eq!(pinned_subdirs(Lang::Rust), &["target"]);
        assert!(pinned_subdirs(Lang::C).is_empty());
    }

    #[test]
    fn cold_baseline_is_not_warm() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _g = PoolDirGuard::set(tmp.path());
        let baseline = Baseline::ensure(Lang::JavaScript).expect("baseline root");
        assert!(!baseline.is_warm(), "empty baseline must be cold");
    }

    #[test]
    fn warm_baseline_snapshots_into_workdir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _g = PoolDirGuard::set(tmp.path());
        let baseline = Baseline::ensure(Lang::JavaScript).expect("baseline root");

        // Warm the baseline: write a fake node_modules tree into the root.
        let pkg = baseline.root().join("node_modules").join("left-pad");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("index.js"), b"module.exports = 1;\n").unwrap();
        assert!(baseline.is_warm(), "populated baseline must report warm");

        // Snapshot it into a fresh per-finding workdir.
        let workdir = tempfile::TempDir::new().unwrap();
        baseline.snapshot_into(workdir.path()).unwrap();
        let cloned = workdir.path().join("node_modules").join("left-pad").join("index.js");
        assert!(cloned.exists(), "snapshot must materialise node_modules");
        assert_eq!(fs::read(&cloned).unwrap(), b"module.exports = 1;\n");
    }

    #[test]
    fn snapshot_of_cold_baseline_is_noop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _g = PoolDirGuard::set(tmp.path());
        let baseline = Baseline::ensure(Lang::Rust).expect("baseline root");
        let workdir = tempfile::TempDir::new().unwrap();
        // No pinned subdir present → snapshot succeeds and writes nothing.
        baseline.snapshot_into(workdir.path()).unwrap();
        assert!(!workdir.path().join("target").exists());
    }
}
