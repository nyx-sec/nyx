//! A source that lives in a test file (mock request data) must not produce a
//! finding against a production sink, while the production handler's own
//! flow is still reported.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

#[test]
fn test_file_mock_source_does_not_reach_production_sink() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("cross_file_js_test_mock_source");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
    let redirects: Vec<_> = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-open-redirect"))
        .collect();
    assert_eq!(
        redirects.len(),
        1,
        "only the production handler's own flow remains: {:?}",
        redirects
            .iter()
            .map(|d| (&d.id, &d.path))
            .collect::<Vec<_>>()
    );
    assert!(
        !redirects[0].id.contains("3:21"),
        "the mock request in the test file is not a source: {}",
        redirects[0].id
    );
}
