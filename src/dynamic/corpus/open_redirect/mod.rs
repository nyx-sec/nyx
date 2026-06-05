//! Open-redirect (`Cap::OPEN_REDIRECT`) per-language payload slices.
//!
//! Phase 09 (Track J.7) carves open redirects across the seven HTTP
//! framework ecosystems Nyx supports: Java
//! (`HttpServletResponse.sendRedirect`), Python (`flask.redirect`),
//! PHP (Symfony `Response::redirect` / Slim `Response::withHeader`),
//! Ruby (`Rack::Response#redirect`), JavaScript (Express
//! `res.redirect`), Go (`gin.Context.Redirect`), Rust (`axum::response::
//! Redirect::to`).  Every vuln payload binds an absolute attacker URL
//! (`https://attacker.test/`) into the response writer's redirect
//! entry point; the paired benign control redirects to a same-origin
//! path (`/dashboard`).  The harness's instrumented redirect shim
//! records a [`crate::dynamic::probe::ProbeKind::Redirect { location,
//! request_host }`] probe with the unmodified location and the
//! request's origin host, and the
//! [`crate::dynamic::oracle::ProbePredicate::RedirectHostNotIn`]
//! predicate fires when the captured `location` resolves off-origin
//! relative to `allowlist ∪ {request_host}`.

pub mod go;
pub mod java;
pub mod js;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;
