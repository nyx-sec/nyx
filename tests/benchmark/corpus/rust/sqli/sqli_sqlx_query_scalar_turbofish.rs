use sqlx::PgPool;
use std::env;

async fn count_orders(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let status = env::var("ORDER_STATUS").unwrap();
    let sql = format!("SELECT COUNT(*) FROM orders WHERE status = '{}'", status);
    sqlx::query_scalar::<_, i64>(&sql).fetch_one(pool).await
}
