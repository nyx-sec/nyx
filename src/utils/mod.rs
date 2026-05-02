//! Shared utilities and configuration.
//!
//! Re-exports [`Config`], [`AnalysisOptions`], and [`DetectorOptions`] from
//! their submodules. [`Config`] is loaded from `nyx.conf` and passed through
//! the top-level call stack. [`AnalysisOptions`] is installed once per process
//! via an `OnceLock` and read back via [`analysis_options::get`] from deep
//! inside the analysis pipeline without threading it through every call frame.
//!
//! Other submodules: `path` (root-relative path utilities and traversal guards),
//! `project` (framework detection, project metadata), `query_cache` (cached
//! tree-sitter query compilation), `snippet` (source snippet extraction for
//! finding locations).

pub mod analysis_options;
pub mod config;
pub mod detector_options;
pub(crate) mod ext;
pub mod path;
pub mod project;
pub(crate) mod query_cache;
pub(crate) mod snippet;

pub use analysis_options::{AnalysisOptions, SymexOptions};
pub use config::Config;
pub use detector_options::{DataExfilDetectorOptions, DetectorOptions};
pub use project::{detect_frameworks, get_project_info};
