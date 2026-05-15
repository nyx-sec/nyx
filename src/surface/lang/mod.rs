//! Per-language framework probes.
//!
//! Phase 21 shipped Python + Flask.  Phase 22 generalises detection to:
//! Python (FastAPI, Django), JS/TS (Express, Koa, Next.js), Java
//! (Spring, Servlet/JAX-RS, Quarkus), Go (`net/http`, gin), PHP
//! (Laravel, Slim), Ruby (Sinatra, Rails), Rust (axum, actix-web).
//!
//! Every probe exposes one public `detect_<framework>_routes` function
//! returning `Vec<SurfaceNode>` (one [`super::SurfaceNode::EntryPoint`]
//! per recognised route).  Probes are pure functions — no I/O, no
//! state.

pub mod common;

pub mod python_flask;
pub mod python_fastapi;
pub mod python_django;

pub mod js_express;
pub mod js_koa;
pub mod ts_next;

pub mod java_spring;
pub mod java_servlet;
pub mod java_quarkus;

pub mod go_http;
pub mod go_gin;

pub mod php_laravel;
pub mod php_slim;

pub mod ruby_sinatra;
pub mod ruby_rails;

pub mod rust_actix;
pub mod rust_axum;
