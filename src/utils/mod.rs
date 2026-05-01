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
