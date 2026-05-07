//! Phase 06 integration tests for `Cap::SSTI`.
//!
//! Fixtures under `tests/fixtures/ssti/<lang>/`:
//!
//! * `unsafe_*` — taint flows from a request source into a template
//!   compile / from_string / render call as the template *source* arg.
//!   Must produce >=1 `taint-template-injection` finding.
//! * `safe_*_constant` — template source is a literal; variables at
//!   render time may carry user input but do not activate SSTI.  Must
//!   produce 0 findings.

mod common;

use common::count_by_prefix;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

const RULE_PREFIX: &str = "taint-template-injection";

fn fixture_dir(lang: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("ssti")
        .join(lang)
}

fn test_config() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.scanner.enable_state_analysis = true;
    cfg.scanner.enable_auth_analysis = true;
    cfg.scanner.include_nonprod = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 64;
    cfg.performance.channel_multiplier = 1;
    cfg
}

fn scan_dir(path: &Path) -> Vec<Diag> {
    nyx_scanner::scan_no_index(path, &test_config()).expect("scan_no_index should succeed")
}

fn diags_for_file(dir: &Path, file_suffix: &str) -> Vec<Diag> {
    scan_dir(dir)
        .into_iter()
        .filter(|d| {
            std::path::Path::new(&d.path)
                .file_name()
                .and_then(|s| s.to_str())
                == Some(file_suffix)
        })
        .collect()
}

fn assert_unsafe(lang: &str, file_suffix: &str) {
    let dir = fixture_dir(lang);
    let diags = diags_for_file(&dir, file_suffix);
    let count = count_by_prefix(&diags, RULE_PREFIX);
    assert!(
        count >= 1,
        "{lang}/{file_suffix}: expected >=1 {RULE_PREFIX} finding, got {count}.\n\
         All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{} [{}] {}", d.path, d.line, d.severity.as_db_str(), d.id))
            .collect::<Vec<_>>(),
    );
}

fn assert_clean(lang: &str, file_suffix: &str) {
    let dir = fixture_dir(lang);
    let diags = diags_for_file(&dir, file_suffix);
    let matching: Vec<_> = diags.iter().filter(|d| d.id.starts_with(RULE_PREFIX)).collect();
    assert!(
        matching.is_empty(),
        "{lang}/{file_suffix}: expected 0 {RULE_PREFIX} findings, got {}:\n{:#?}",
        matching.len(),
        matching
            .iter()
            .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn javascript_handlebars_compile_with_tainted_source_fires() {
    assert_unsafe("javascript", "unsafe_handlebars_compile.js");
}

#[test]
fn javascript_handlebars_constant_source_does_not_fire() {
    assert_clean("javascript", "safe_handlebars_constant.js");
}

#[test]
fn typescript_handlebars_compile_with_tainted_source_fires() {
    assert_unsafe("typescript", "unsafe_handlebars_compile.ts");
}

#[test]
fn typescript_handlebars_constant_source_does_not_fire() {
    assert_clean("typescript", "safe_handlebars_constant.ts");
}

#[test]
fn python_jinja_template_with_tainted_source_fires() {
    assert_unsafe("python", "unsafe_jinja_template.py");
}

#[test]
fn python_jinja_constant_source_does_not_fire() {
    assert_clean("python", "safe_jinja_constant.py");
}

#[test]
fn python_jinja_compile_expression_with_tainted_source_fires() {
    assert_unsafe("python", "unsafe_jinja_compile_expression.py");
}

#[test]
fn python_render_template_with_tainted_var_does_not_fire() {
    assert_clean("python", "safe_render_template_var.py");
}

#[test]
fn python_mako_lookup_get_template_with_tainted_name_fires() {
    // Mako TemplateLookup.get_template loader-path pattern.  Tainted
    // `name` selects which file becomes the rendered template — arbitrary
    // template execution modeled as SSTI on the loader-path arg.
    assert_unsafe("python", "unsafe_mako_lookup_get_template.py");
}

#[test]
fn python_mako_lookup_constant_name_does_not_fire() {
    assert_clean("python", "safe_mako_lookup_constant.py");
}

#[test]
fn python_jinja_get_template_with_tainted_name_fires() {
    // Jinja2 Environment.get_template loader-path pattern.
    assert_unsafe("python", "unsafe_jinja_get_template.py");
}

#[test]
fn javascript_nunjucks_render_string_tainted_source_fires() {
    assert_unsafe("javascript", "unsafe_nunjucks_render_string.js");
}

#[test]
fn javascript_nunjucks_render_string_const_template_does_not_fire() {
    assert_clean("javascript", "safe_nunjucks_render_string.js");
}

#[test]
fn typescript_nunjucks_render_string_tainted_source_fires() {
    assert_unsafe("typescript", "unsafe_nunjucks_render_string.ts");
}

#[test]
fn typescript_nunjucks_render_string_const_template_does_not_fire() {
    assert_clean("typescript", "safe_nunjucks_render_string.ts");
}

#[test]
fn php_twig_create_template_with_tainted_source_fires() {
    assert_unsafe("php", "unsafe_twig_create_template.php");
}

#[test]
fn php_twig_constant_source_does_not_fire() {
    assert_clean("php", "safe_twig_constant.php");
}

#[test]
fn php_twig_render_with_tainted_var_does_not_fire() {
    assert_clean("php", "safe_twig_template_var.php");
}

#[test]
fn php_smarty_string_prefix_with_tainted_source_fires() {
    assert_unsafe("php", "unsafe_smarty_string_fetch.php");
}

#[test]
fn php_smarty_file_fetch_with_tainted_var_does_not_fire() {
    assert_clean("php", "safe_smarty_file_fetch.php");
}

#[test]
fn java_freemarker_with_tainted_template_source_fires() {
    assert_unsafe("java", "UnsafeFreemarkerTemplate.java");
}

#[test]
fn java_freemarker_constant_template_does_not_fire() {
    assert_clean("java", "SafeFreemarkerConstant.java");
}

#[test]
fn java_freemarker_template_process_with_tainted_source_fires() {
    assert_unsafe("java", "UnsafeFreemarkerProcess.java");
}

#[test]
fn ruby_erb_new_with_tainted_source_fires() {
    assert_unsafe("ruby", "unsafe_erb_new.rb");
}

#[test]
fn ruby_erb_constant_source_does_not_fire() {
    assert_clean("ruby", "safe_erb_constant.rb");
}

#[test]
fn ruby_render_template_with_tainted_var_does_not_fire() {
    assert_clean("ruby", "safe_erb_template_var.rb");
}

#[test]
fn go_text_template_parse_with_tainted_source_fires() {
    assert_unsafe("go", "unsafe_template_parse.go");
}

#[test]
fn go_template_constant_source_does_not_fire() {
    assert_clean("go", "safe_template_constant.go");
}

#[test]
fn go_template_parse_files_with_tainted_var_does_not_fire() {
    assert_clean("go", "safe_template_parsefiles.go");
}
