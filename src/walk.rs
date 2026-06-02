//! Filesystem walker with batched path delivery.
//!
//! Builds an [`ignore`]-crate [`WalkBuilder`] from the config (respecting
//! `.gitignore`, excluded directories, and excluded extensions), then delivers
//! discovered paths to the analysis pipeline in batches over a crossbeam channel.
//! Batching amortizes channel overhead for large trees.
//!
//! All paths are checked via [`crate::utils::path::path_stays_within_root`]
//! before entering a batch, preventing traversal outside the scan root.

use crate::utils::Config;
use crate::utils::path::path_stays_within_root;
use crossbeam_channel::{Receiver, Sender, bounded};
use ignore::{WalkBuilder, WalkState, overrides::OverrideBuilder};
use std::thread::JoinHandle;
use std::{
    mem,
    path::{Path, PathBuf},
    thread,
};

// Internal constants / helpers

type Paths = Vec<PathBuf>;

struct BatchSender {
    tx: Sender<Paths>,
    batch: Paths,
    batch_size: usize,
}
impl BatchSender {
    fn new(tx: Sender<Paths>, batch_size: usize) -> Self {
        Self {
            tx,
            batch: Vec::with_capacity(batch_size),
            batch_size,
        }
    }

    fn push_path(&mut self, path: PathBuf) {
        self.batch.push(path);
        if self.batch.len() >= self.batch_size {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if !self.batch.is_empty() {
            tracing::debug!(n_paths = self.batch.len(), "flushing batch");
            let _ = self.tx.send(mem::take(&mut self.batch));
        }
    }
}
impl Drop for BatchSender {
    fn drop(&mut self) {
        self.flush();
    }
}

fn build_overrides(root: &Path, cfg: &Config) -> ignore::overrides::Override {
    let mut ob = OverrideBuilder::new(root);

    for ext in &cfg.scanner.excluded_extensions {
        if let Err(e) = ob.add(&format!("!*.{ext}")) {
            tracing::warn!("invalid exclude‐extension pattern ‘{ext}’: {e}");
        }
    }
    for dir in &cfg.scanner.excluded_directories {
        if let Err(e) = ob.add(&format!("!**/{dir}/**")) {
            tracing::warn!("invalid exclude‐dir pattern ‘{dir}’: {e}");
        }
    }
    for file in &cfg.scanner.excluded_files {
        if let Err(e) = ob.add(&format!("!{file}")) {
            tracing::warn!("invalid exclude‐file pattern ‘{file}’: {e}");
        }
    }
    // Whitelist: when any include path is present, the override engine scans
    // only files matching an include glob (intersected with the excludes above).
    for inc in &cfg.scanner.included_paths {
        let inc = inc.trim_end_matches('/');
        if let Err(e) = ob.add(inc) {
            tracing::warn!("invalid include‐path pattern ‘{inc}’: {e}");
        }
        if let Err(e) = ob.add(&format!("{inc}/**")) {
            tracing::warn!("invalid include‐path pattern ‘{inc}/**’: {e}");
        }
    }

    ob.build().unwrap_or_else(|e| {
        tracing::error!("failed to build ignore overrides: {e}");
        ignore::overrides::Override::empty()
    })
}

/// Walk `root` and send *batches* of paths through the returned channel.
pub fn spawn_file_walker(root: &Path, cfg: &Config) -> (Receiver<Paths>, JoinHandle<()>) {
    let _span = tracing::info_span!("spawn_file_walker", root = %root.display()).entered();
    let overrides = build_overrides(root, cfg);

    // ----- 2  channel & thread pool parameters -----------------------------
    let workers = cfg.performance.worker_threads.unwrap_or(num_cpus::get());
    let (tx, rx) = bounded::<Paths>(workers * cfg.performance.channel_multiplier);

    let root = root.to_path_buf();
    let canonical_root = std::fs::canonicalize(&root).ok();
    let scan_hidden = cfg.scanner.scan_hidden_files;
    let follow = cfg.scanner.follow_symlinks;
    let max_bytes = cfg.scanner.max_file_size_mb.unwrap_or(0) * 1_048_576;
    let batch_size = cfg.performance.batch_size;
    let max_depth = cfg.performance.max_depth;
    let same_file_system = cfg.scanner.one_file_system;
    let require_git = cfg.scanner.require_git_to_read_vcsignore;

    // ----- 3  the background walker thread ---------------------------------
    let handle = thread::spawn(move || {
        tracing::info!(
            root = ?root,
            workers = workers,
            scan_hidden = scan_hidden,
            follow_links = follow,
            max_bytes = max_bytes,
            batch_size = batch_size,
            "starting directory walk"
        );

        let mut builder = WalkBuilder::new(root);
        builder
            .hidden(!scan_hidden)
            .follow_links(follow)
            .threads(workers)
            .overrides(overrides)
            .same_file_system(same_file_system)
            .require_git(require_git);
        if let Some(depth) = max_depth {
            builder.max_depth(Some(depth));
        }
        builder
            .filter_entry(|e| {
                e.file_type()
                    .map(|ft| ft.is_dir() || ft.is_file())
                    .unwrap_or(true)
            })
            .build_parallel()
            .run(move || {
                let mut bs = BatchSender::new(tx.clone(), batch_size);
                let canonical_root = canonical_root.clone();

                Box::new(move |entry| {
                    if let Ok(e) = entry {
                        let metadata = match e.metadata() {
                            Ok(metadata) => metadata,
                            Err(_) => return WalkState::Continue,
                        };
                        let is_file = metadata.file_type().is_file();
                        let under_limit = max_bytes == 0 || metadata.len() <= max_bytes;
                        // Always canonicalize and verify containment, a symlink
                        // in the tree can escape the root even when follow=false
                        // if the walker resolves it at metadata time.
                        let path_allowed = canonical_root.as_ref().is_none_or(|root| {
                            path_stays_within_root(root, e.path()).unwrap_or(false)
                        });

                        if is_file && under_limit && path_allowed {
                            bs.push_path(e.into_path());
                        }
                    }
                    WalkState::Continue
                })
            });
        tracing::info!("directory walk complete");
    });

    (rx, handle)
}

#[test]
fn walker_respects_excluded_extensions() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("keep.rs"), "fn main(){}").unwrap(); // nyx:ignore cfg-unguarded-sink
    std::fs::write(tmp.path().join("skip.txt"), "ignored").unwrap(); // nyx:ignore cfg-unguarded-sink

    let mut cfg = Config::default();
    cfg.scanner.excluded_extensions = vec!["txt".into()];
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let (rx, handle) = spawn_file_walker(tmp.path(), &cfg);
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
    }

    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(all.iter().any(|p| p.ends_with("keep.rs")));
    assert!(all.iter().all(|p| !p.ends_with("skip.txt")));
}

#[test]
fn walker_respects_excluded_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Files at root level
    std::fs::write(root.join("keep.rs"), "fn main(){}").unwrap(); // nyx:ignore cfg-unguarded-sink
    // Files in excluded subdir
    let vendor = root.join("vendor");
    std::fs::create_dir(&vendor).unwrap();
    std::fs::write(vendor.join("dep.rs"), "fn dep(){}").unwrap(); // nyx:ignore cfg-unguarded-sink

    let mut cfg = Config::default();
    cfg.scanner.excluded_directories = vec!["vendor".into()];
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 4;

    let (rx, handle) = spawn_file_walker(root, &cfg);
    handle.join().ok();
    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(all.iter().any(|p| p.ends_with("keep.rs")));
    assert!(
        all.iter().all(|p| !p.starts_with(&vendor)),
        "vendor dir files should be excluded: {all:?}"
    );
}

#[test]
fn walker_respects_excluded_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    std::fs::write(root.join("keep.rs"), "fn a(){}").unwrap(); // nyx:ignore cfg-unguarded-sink
    std::fs::write(root.join("skip.rs"), "fn b(){}").unwrap(); // nyx:ignore cfg-unguarded-sink

    let mut cfg = Config::default();
    cfg.scanner.excluded_files = vec!["skip.rs".into()];
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 4;

    let (rx, handle) = spawn_file_walker(root, &cfg);
    handle.join().ok();
    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(all.iter().any(|p| p.ends_with("keep.rs")));
    assert!(all.iter().all(|p| !p.ends_with("skip.rs")));
}

#[test]
fn walker_respects_max_file_size() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Write a small file (a few bytes) and a large file (> 1 MB limit)
    std::fs::write(root.join("small.rs"), "fn s(){}").unwrap(); // nyx:ignore cfg-unguarded-sink
    let big_data = vec![b'x'; 2 * 1_048_576]; // 2 MB
    std::fs::write(root.join("big.rs"), big_data).unwrap(); // nyx:ignore cfg-unguarded-sink

    let mut cfg = Config::default();
    cfg.scanner.max_file_size_mb = Some(1); // 1 MB limit
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 4;

    let (rx, handle) = spawn_file_walker(root, &cfg);
    handle.join().ok();
    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(all.iter().any(|p| p.ends_with("small.rs")));
    assert!(
        all.iter().all(|p| !p.ends_with("big.rs")),
        "file exceeding size limit should be excluded: {all:?}"
    );
}

#[test]
fn walker_returns_empty_on_empty_directory() {
    let tmp = tempfile::tempdir().unwrap();

    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 4;

    let (rx, handle) = spawn_file_walker(tmp.path(), &cfg);
    handle.join().ok();
    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(all.is_empty(), "empty directory should yield no files");
}

#[cfg(unix)]
#[test]
fn walker_follow_symlinks_does_not_escape_root() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("secret.rs");
    std::fs::write(&outside_file, "fn leaked() {}").unwrap();

    let link = tmp.path().join("escape.rs");
    symlink(&outside_file, &link).unwrap();

    let mut cfg = Config::default();
    cfg.scanner.follow_symlinks = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 4;

    let (rx, handle) = spawn_file_walker(tmp.path(), &cfg);
    handle.join().ok();
    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(
        all.iter().all(|path| path != &link),
        "symlink escapes must not be scanned: {all:?}"
    );
}

#[cfg(unix)]
#[test]
fn walker_no_follow_symlinks_still_rejects_outside_paths() {
    // Pre-existing symlink to an out-of-root file must be excluded even when
    // follow_symlinks=false, the walker may surface the resolved path on
    // some platforms.
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("secret.rs");
    std::fs::write(&outside_file, "fn leaked() {}").unwrap();

    let link = tmp.path().join("escape.rs");
    symlink(&outside_file, &link).unwrap();

    let mut cfg = Config::default();
    cfg.scanner.follow_symlinks = false;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 4;

    let (rx, handle) = spawn_file_walker(tmp.path(), &cfg);
    handle.join().ok();
    let all: Vec<_> = rx.into_iter().flatten().collect();

    assert!(
        all.iter()
            .all(|path| !path.starts_with(outside.path()) && path != &link),
        "symlink target outside root must not be scanned: {all:?}"
    );
}
