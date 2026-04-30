//! `Cap::DATA_EXFIL` suppression-layer integration tests.
//!
//! Three layers are exercised:
//!
//!   1. Sanitizer convention. `logEvent({user: req.cookies.session})`
//!      routes a Sensitive cookie source through a named telemetry
//!      boundary; the default sanitizer rule for `logEvent` clears the
//!      cap.
//!   2. Per-project destination allowlist. With
//!      `[detectors.data_exfil.trusted_destinations] = ["https://api.internal/"]`
//!      installed via the runtime, a `fetch('https://api.internal/...',
//!      {body: tainted})` call has the cap suppressed for that gate only;
//!      a `fetch('https://untrusted.example.com/...', ...)` call on a
//!      destination NOT in the allowlist still emits the finding.
//!   3. Detector-class enabled toggle. When
//!      `[detectors.data_exfil.enabled] = false` is installed, no
//!      `taint-data-exfiltration` finding is emitted regardless of which
//!      gate would have fired.
//!
//! All sub-cases run inside a single `#[test]` so the global
//! `detector_options` runtime is mutated sequentially.  Each sub-case
//! installs its own configuration via `reinstall` and resets to defaults
//! at the end so other test binaries are unaffected.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use nyx_scanner::utils::detector_options::{DataExfilDetectorOptions, DetectorOptions, reinstall};
use std::path::PathBuf;

fn js_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("js")
}

fn diags_for(file: &str) -> Vec<Diag> {
    let dir = js_fixture_dir();
    let all = scan_fixture_dir(&dir, AnalysisMode::Full);
    all.into_iter().filter(|d| d.path.ends_with(file)).collect()
}

fn count_data_exfil(diags: &[Diag]) -> usize {
    diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .count()
}

fn install_default_detectors() {
    reinstall(DetectorOptions::default());
}

fn install_with_trusted(prefixes: &[&str]) {
    reinstall(DetectorOptions {
        data_exfil: DataExfilDetectorOptions {
            enabled: true,
            trusted_destinations: prefixes.iter().map(|s| (*s).to_string()).collect(),
        },
    });
}

fn install_disabled() {
    reinstall(DetectorOptions {
        data_exfil: DataExfilDetectorOptions {
            enabled: false,
            trusted_destinations: Vec::new(),
        },
    });
}

#[test]
fn data_exfil_suppression_suite() {
    // ── 1. sanitizer-convention: `logEvent` clears the cap.
    install_default_detectors();
    let diags = diags_for("fetch_data_exfil_sanitizer_wrap.js");
    assert_eq!(
        count_data_exfil(&diags),
        0,
        "logEvent default sanitizer must clear DATA_EXFIL.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );

    // ── 2a. allowlist drops cap on trusted destination.
    install_with_trusted(&["https://api.internal/"]);
    let diags = diags_for("fetch_data_exfil_allowlist_suppressed.js");
    assert_eq!(
        count_data_exfil(&diags),
        0,
        "trusted destination prefix must drop DATA_EXFIL for that filter.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );

    // ── 2b. negative: a destination NOT in the allowlist still fires.
    install_with_trusted(&["https://api.internal/"]);
    let diags = diags_for("fetch_data_exfil_external_destination.js");
    assert!(
        count_data_exfil(&diags) >= 1,
        "destination not in allowlist must still emit DATA_EXFIL.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );

    // ── 3a. detector toggle off ⇒ no DATA_EXFIL anywhere.
    install_disabled();
    let diags_internal = diags_for("fetch_data_exfil_allowlist_suppressed.js");
    let diags_external = diags_for("fetch_data_exfil_external_destination.js");
    let diags_classic = diags_for("fetch_body_data_exfil.js");
    assert_eq!(
        count_data_exfil(&diags_internal),
        0,
        "enabled=false must suppress DATA_EXFIL on the internal-destination fixture",
    );
    assert_eq!(
        count_data_exfil(&diags_external),
        0,
        "enabled=false must suppress DATA_EXFIL on the external-destination fixture",
    );
    assert_eq!(
        count_data_exfil(&diags_classic),
        0,
        "enabled=false must suppress DATA_EXFIL on the original cookie-leak fixture",
    );

    // ── 3b. re-enable ⇒ classic cookie-leak fixture fires again
    //         (regression guard for the toggle).
    install_default_detectors();
    let diags_classic = diags_for("fetch_body_data_exfil.js");
    assert!(
        count_data_exfil(&diags_classic) >= 1,
        "after re-enabling, the classic cookie-leak fixture must emit DATA_EXFIL again",
    );

    // Reset to defaults so other test binaries running later in the same
    // process pick up the documented baseline.
    install_default_detectors();
}
