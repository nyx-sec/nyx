//! Multi-language static vulnerability scanner.
//!
//! Tree-sitter parsing, petgraph CFGs, SSA-based dataflow, and cross-file
//! taint analysis with a capability-based sanitizer system. Supports Rust,
//! C, C++, Java, Go, PHP, Python, Ruby, TypeScript, and JavaScript.
//!
//! This crate is both the `nyx` binary and a library for programmatic
//! scanning. Most internal modules are public for testing and downstream
//! tooling, but the stable contract is [`scan_no_index`] plus the types
//! it returns.
//!
//! For a description of how the analysis pipeline works, see the
//! [how-it-works handbook](https://github.com/elicpeter/nyx/blob/master/docs/how-it-works.md).
//! Per-detector documentation lives on the [`taint`], [`cfg_analysis`],
//! [`state`], [`patterns`], and [`auth_analysis`] module pages.
//!
//! # Entry points
//!
//! [`scan_no_index`] runs a full two-pass scan over a directory tree and
//! returns a flat list of [`commands::scan::Diag`] values. It does not
//! touch a SQLite index; every file is analysed from disk on each call.
//!
//! ```no_run
//! use nyx_scanner::{scan_no_index, utils::Config};
//! use std::path::Path;
//!
//! let config = Config::default();
//! let findings = scan_no_index(Path::new("/path/to/project"), &config).unwrap();
//! for diag in &findings {
//!     println!("{} at {}:{}", diag.id, diag.path, diag.line);
//! }
//! ```
//!
//! For incremental rescanning backed by a SQLite index, use
//! [`commands::scan::scan_with_index_parallel`] directly.
//!
//! # Key types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`utils::config::Config`] | Top-level scanner config (load from `nyx.conf` or construct in code) |
//! | [`commands::scan::Diag`] | A single finding: location, severity, rule ID, structured evidence |
//! | [`evidence::Evidence`] | Source/sink spans, flow steps, sanitizer annotations, engine notes |
//! | [`evidence::Confidence`] | Low / Medium / High confidence tag |
//! | [`labels::Cap`] | Bitflag capability set describing what a taint flow can reach |
//! | [`symbol::Lang`] | Supported language enum |
//! | [`symbol::FuncKey`] | Canonical cross-file function identity |
//!
//! # Reading findings
//!
//! Each [`commands::scan::Diag`] carries:
//!
//! - `path`, `line`, `col` — source location of the sink
//! - `id` — rule identifier (e.g. `taint-unsanitised-flow`, `cfg-auth-gap`)
//! - `severity` — Critical / High / Medium / Low / Info
//! - `confidence` — Low / Medium / High; capped at Medium when an engine
//!   budget was hit
//! - `rank_score` — deterministic attack-surface score for truncation ordering
//! - `evidence` — optional [`evidence::Evidence`] with source/sink spans,
//!   flow steps, and [`engine_notes::EngineNote`] values describing precision loss
//!
//! Engine notes communicate when a bound was hit. A finding carrying
//! `EngineNote::OriginsTruncated` or `EngineNote::SccBudgetExhausted` is
//! still real, but the engine had less information than it would have had
//! without the cap.
//!
//! # Module map
//!
//! | Module | Role |
//! |--------|------|
//! | [`ast`] | Tree-sitter parsing and two-pass analysis dispatch |
//! | [`mod@cfg`] | CFG construction from ASTs |
//! | [`ssa`] | SSA lowering and optimization passes |
//! | [`taint`] | Forward SSA taint analysis |
//! | [`cfg_analysis`] | Structural CFG checks (auth gaps, resource leaks, error paths) |
//! | [`state`] | Resource lifecycle and state-machine analysis |
//! | [`patterns`] | Pattern-based AST checks |
//! | [`auth_analysis`] | Missing authorization / ownership checks |
//! | [`callgraph`] | Whole-program call graph and SCC analysis |
//! | [`summary`] | Per-function summaries for cross-file resolution |
//! | [`labels`] | Source, sanitizer, and sink rule registries per language |
//! | [`symex`] | Symbolic execution for witness generation and path feasibility |
//! | [`abstract_interp`] | Interval and string bounds propagation for sink suppression |
//! | [`constraint`] | Path constraint solving and infeasible-path pruning |
//! | [`evidence`] | Finding provenance and confidence types |
//! | [`suppress`] | Inline `nyx:ignore` directive handling |
//! | [`output`] | JSON and SARIF serialization |
//! | [`database`] | SQLite index pool and schema |
//! | [`walk`] | Filesystem traversal with batched delivery |

pub mod abstract_interp;
pub mod ast;
pub mod auth_analysis;
pub mod callgraph;
pub mod cfg;
pub mod cfg_analysis;
pub mod cli;
pub mod commands;
pub mod constraint;
pub mod convergence_telemetry;
pub mod database;
pub mod engine_notes;
pub mod entry_points;
pub mod errors;
pub mod evidence;
pub mod fmt;
pub mod interop;
pub mod labels;
pub mod output;
pub mod patterns;
pub mod pointer;
pub mod rank;
pub mod resolve;
pub mod rust_resolve;
#[cfg(feature = "serve")]
pub mod server;
pub mod ssa;
pub mod state;
pub mod summary;
pub mod suppress;
pub mod symbol;
pub mod symex;
pub mod taint;
pub mod utils;
pub mod walk;

use errors::NyxResult;
use std::path::Path;
use utils::config::Config;

/// Run a two-pass scan over `root` without an incremental index.
///
/// Every file under `root` is analysed from disk on each call; no SQLite
/// state is read or written. The walker respects `.gitignore` files when
/// `cfg.scanner.read_vcsignore` is true (the default), skips hidden files
/// and symlinks unless the config enables them, and excludes the directories
/// and extensions listed in `cfg.scanner.excluded_*`.
///
/// Returns one [`commands::scan::Diag`] per finding. The list is unsorted;
/// call [`rank::rank_diags`] if you need findings ordered by exploitability.
///
/// For indexed / incremental rescanning use
/// [`commands::scan::scan_with_index_parallel`] instead.
pub fn scan_no_index(root: &Path, cfg: &Config) -> NyxResult<Vec<commands::scan::Diag>> {
    commands::scan::scan_filesystem(root, cfg, false)
}
