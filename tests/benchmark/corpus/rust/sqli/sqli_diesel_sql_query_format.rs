use diesel::prelude::*;
use std::env;

fn find_by_name(conn: &mut PgConnection) -> QueryResult<usize> {
    let name = env::var("USERNAME").unwrap();
    let sql = format!("DELETE FROM users WHERE name = '{}'", name);
    diesel::sql_query(sql).execute(conn)
}
