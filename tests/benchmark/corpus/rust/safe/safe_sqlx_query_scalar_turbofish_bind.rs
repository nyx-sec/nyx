use sqlx::PgPool;
use std::env;

async fn count_orders(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let status = env::var("ORDER_STATUS").unwrap();
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orders WHERE status = $1")
        .bind(status)
        .fetch_one(pool)
        .await
}
