//! Server-Side Template Injection (`Cap::SSTI`) per-engine payload slices.
//!
//! Phase 04 (Track J.2) carves SSTI across the five most-common template
//! engines: Jinja2 (Python), ERB (Ruby), Twig (PHP), Thymeleaf (Java), and
//! Handlebars (JavaScript).  Every vuln payload sends a template
//! expression that resolves to a known constant *only* when the engine
//! actually evaluates the expression (e.g. `{{7*7}}` → `49` in Jinja2,
//! `<%= 7*7 %>` → `49` in ERB).  The paired benign control sends the
//! literal arithmetic text without engine markers so the per-engine
//! harness echoes the payload verbatim rather than evaluating it; the
//! oracle's [`crate::dynamic::oracle::ProbePredicate::TemplateEvalEqual`]
//! check fires on the vuln render (`49`) and does not fire on the
//! benign render (`7*7`), satisfying the §4.1 differential rule.

pub mod java_thymeleaf;
pub mod js_handlebars;
pub mod php_twig;
pub mod python_jinja2;
pub mod ruby_erb;
