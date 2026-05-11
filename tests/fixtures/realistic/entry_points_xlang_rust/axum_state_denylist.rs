// Rust entry-point seeding precision negative.  `State<Arc<DbPool>>`
// is a DI handle, not a request-bound user input.  The taint engine
// must NOT paint `pool` as Source, otherwise every DB sink consuming
// the pool reads as adversary-controlled.
//
// The structural cfg-unguarded-sink rule may still fire on the
// generic `diesel::sql_query("...").execute(...)` chain (literal arg,
// receiver chain), so this fixture forbids only the
// `taint-unsanitised-flow` flavour.  That is the FP regression we
// guard against once scoped lowering is enabled for Rust handlers.
use axum::extract::State;
use std::sync::Arc;

pub struct DbPool;

impl DbPool {
    pub fn exec(&self, _q: &str) {}
}

pub async fn list(State(pool): State<Arc<DbPool>>) -> String {
    diesel::sql_query("SELECT 1").execute(&pool);
    String::new()
}

pub async fn safe(State(pool): State<Arc<DbPool>>) -> String {
    pool.exec("SELECT 2");
    String::new()
}

mod diesel {
    pub fn sql_query(_: &str) -> SqlQuery {
        SqlQuery
    }
    pub struct SqlQuery;
    impl SqlQuery {
        pub fn execute<T>(&self, _: T) {}
    }
}
