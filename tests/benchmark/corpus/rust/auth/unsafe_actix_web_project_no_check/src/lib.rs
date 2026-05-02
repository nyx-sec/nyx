//! Regression counterpart to `safe_non_web_rust_project`.  Same helper
//! shape (`fn delete_session(session_id: i64)`) with NO upstream auth
//! check — must still flag missing_ownership_check because the
//! project's manifest names `actix-web` → web-framework signal
//! `Some(true)` → the param-name heuristic stays on.

pub struct Db;
impl Db {
    pub async fn delete_one(&self, _id: i64) -> Result<(), ()> { Ok(()) }
}

// Helper called from an actix handler.  No upstream `require_*` /
// `check_*` covers `session_id`, so missing_ownership_check fires.
pub async fn delete_session(db: &Db, session_id: i64) -> Result<(), ()> {
    db.delete_one(session_id).await
}
