//! A member read hoisted out of a call's arguments (`location.search` in a
//! `useEffect` dependency array) names no call of its node, so it must not
//! bind to a same-leaf method (`MailClient.search`) in another file.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

#[test]
fn hoisted_member_read_does_not_bind_a_project_method() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("cross_file_js_hoisted_member_read");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
