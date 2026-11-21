use sqlx::SqlitePool;
use std::env;

async fn purge(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let table = env::var("TARGET_TABLE").unwrap();
    // The bound value is fine, but the table name is spliced into the SQL text.
    let sql = format!("DELETE FROM {} WHERE owner = ?", table);
    let res = sqlx::query(&sql).bind(42_i64).execute(pool).await?;
    Ok(res.rows_affected())
}
