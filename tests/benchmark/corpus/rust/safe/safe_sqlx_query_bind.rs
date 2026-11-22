use sqlx::SqlitePool;
use std::env;

async fn rename(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let new_name = env::var("NEW_NAME").unwrap();
    let res = sqlx::query("UPDATE accounts SET name = ? WHERE id = ?")
        .bind(new_name)
        .bind(1_i64)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
