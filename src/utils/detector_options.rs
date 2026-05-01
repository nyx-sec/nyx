//! Per-detector runtime options.
//!
//! Mirrors the install/current pattern in [`crate::utils::analysis_options`]
//! but for detector-class knobs that live under `[detectors.*]` in
//! `nyx.conf`.  Engine code that wants to consult a detector option calls
//! [`current`]; the CLI installs a resolved value before the scan starts.
//!
//! The first knobs covered here are the [`Cap::DATA_EXFIL`][crate::labels::Cap::DATA_EXFIL]
//! suppression layers:
//!
//! * `enabled` — turn the cap off entirely per-project so legitimate
//!   forwarding pipelines don't surface findings.
//! * `trusted_destinations` — destination URL prefixes that suppress the
//!   cap when a sink's URL argument has a static prefix matching one of
//!   them.  Uses the same prefix-lock plumbing the SSRF suppression has.
//!
//! Defaults are conservative: detector enabled, no trusted destinations.

use serde::{Deserialize, Serialize};
use std::sync::RwLock;

/// Options for the `Cap::DATA_EXFIL` suppression layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DataExfilDetectorOptions {
    /// When `false`, the entire data-exfiltration detector class is
    /// suppressed for the project.  Sink-time filters drop
    /// [`crate::labels::Cap::DATA_EXFIL`] from sink caps before event
    /// emission, so no `taint-data-exfiltration` findings reach output.
    pub enabled: bool,
    /// URL prefixes treated as trusted destinations for outbound
    /// requests.  When a sink's destination argument has a proven static
    /// prefix (from the abstract string domain or an inline literal)
    /// that begins with one of these entries, the
    /// [`crate::labels::Cap::DATA_EXFIL`] bit is dropped before event
    /// emission.  Mirrors the SSRF prefix-lock semantics.
    pub trusted_destinations: Vec<String>,
}

impl Default for DataExfilDetectorOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_destinations: Vec::new(),
        }
    }
}

/// Top-level `[detectors]` block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectorOptions {
    pub data_exfil: DataExfilDetectorOptions,
}

static RUNTIME: RwLock<Option<DetectorOptions>> = RwLock::new(None);

/// Install the process-wide detector options.  First-wins: subsequent calls
/// are a no-op and return `false`.  The CLI calls this once per process at
/// scan start; library consumers that never install pick up
/// [`DetectorOptions::default`] via [`current`].
pub fn install(opts: DetectorOptions) -> bool {
    let mut guard = RUNTIME.write().expect("detector options RwLock poisoned");
    if guard.is_some() {
        return false;
    }
    *guard = Some(opts);
    true
}

/// Replace the installed options unconditionally.  Mirrors
/// [`crate::utils::analysis_options::reinstall`] for the server's
/// per-request resolution path.
pub fn reinstall(opts: DetectorOptions) {
    *RUNTIME.write().expect("detector options RwLock poisoned") = Some(opts);
}

/// Read the active options.  Returns the installed runtime when present,
/// otherwise [`DetectorOptions::default`].
pub fn current() -> DetectorOptions {
    RUNTIME
        .read()
        .expect("detector options RwLock poisoned")
        .clone()
        .unwrap_or_default()
}

/// Test helper: clear the installed runtime so a subsequent [`install`]
/// takes effect.  Used only in tests that exercise different detector
/// configurations within the same process.
#[doc(hidden)]
pub fn _reset_for_tests() {
    *RUNTIME.write().expect("detector options RwLock poisoned") = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented() {
        let o = DetectorOptions::default();
        assert!(o.data_exfil.enabled);
        assert!(o.data_exfil.trusted_destinations.is_empty());
    }

    #[test]
    fn toml_roundtrip() {
        let opts = DetectorOptions {
            data_exfil: DataExfilDetectorOptions {
                enabled: false,
                trusted_destinations: vec![
                    "https://api.internal/".into(),
                    "https://telemetry.".into(),
                ],
            },
        };
        let s = toml::to_string(&opts).unwrap();
        let back: DetectorOptions = toml::from_str(&s).unwrap();
        assert_eq!(opts, back);
    }

    #[test]
    fn missing_section_uses_defaults() {
        let toml_str = r#"# empty"#;
        let cfg: DetectorOptions = toml::from_str(toml_str).unwrap();
        assert!(cfg.data_exfil.enabled);
    }
}
