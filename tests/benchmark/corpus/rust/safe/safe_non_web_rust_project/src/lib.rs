//! Real-repo precision guard distilled from zed's desktop / GUI crates
//! (`crates/agent_servers/src/acp.rs::session_thread`,
//! `crates/agent_ui/src/thread_worktree_archive.rs::rollback_persist`,
//! `crates/debugger_ui/src/tests/debugger_panel.rs::test_*`).
//!
//! Without the project-level web-framework signal, two heuristics
//! over-fire on internal helpers in non-web Rust projects:
//!   * `is_external_input_param_name` flips step 3 open on every
//!     `*_id` / `path` / `query` / `body` / `dto` parameter.
//!   * `matches_session_context` lifts every `session.foo` chain into
//!     `unit.context_inputs` (step 2), even when `session` is a
//!     debug / RPC / DAP session, not an HTTP/auth session.
//!
//! Both arms must be gated by the project's web-framework signal.
//! This crate's `Cargo.toml` deliberately names no Rust web framework,
//! so `lang_has_web_framework("rust")` returns `Some(false)` and both
//! arms refuse to count internal-helper params as user input.

pub struct ContextServerStore;
impl ContextServerStore {
    pub fn get_running_server(&self, _: &str) -> Option<()> { Some(()) }
}

pub struct ClientContext {
    pub sessions: Vec<DebugSession>,
}

pub struct DebugSession;
impl DebugSession {
    pub fn update<F: FnOnce(&Self) -> R, R>(&self, f: F) -> R { f(self) }
    pub fn read(&self) -> &Self { self }
    pub fn adapter_client(&self) -> Option<()> { Some(()) }
}

// `<thing>_id` parameter must not gate user-input-evidence open in a
// project the manifest confirmed has no Rust web framework.  Without
// the gate, every helper of this shape would fire missing_ownership_check.
pub fn get_prompt(
    server_store: &ContextServerStore,
    server_id: &str,
    prompt_name: &str,
) -> Option<()> {
    let _ = (server_id, prompt_name);
    server_store.get_running_server(server_id)
}

pub async fn rollback_persist(archived_worktree_id: i64) {
    let _ = archived_worktree_id;
}

// Bare `session.foo` chains land in `context_inputs` via
// `matches_session_context` → `ValueSourceKind::Session`.  In a non-
// web Rust project the gate suppresses step 2 so this idiomatic
// debug-session pattern stays silent.
pub fn open_debug_session(ctx: &ClientContext) {
    if let Some(session) = ctx.sessions.first() {
        let _ = session.update(|session| session.adapter_client());
        let _client = session.read();
    }
}
