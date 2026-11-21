use sqlx::SqlitePool;
use std::env;

#[derive(sqlx::FromRow)]
struct User {
    id: i64,
    name: String,
}

async fn find_user(pool: &SqlitePool) -> Result<Vec<User>, sqlx::Error> {
    let name = env::var("USERNAME").unwrap();
    sqlx::query_as::<_, User>("SELECT id, name FROM users WHERE name = ?")
        .bind(name)
        .fetch_all(pool)
        .await
}
