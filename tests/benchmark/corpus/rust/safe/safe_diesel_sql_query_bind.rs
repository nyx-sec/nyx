use diesel::prelude::*;
use diesel::sql_types::Text;
use std::env;

fn find_by_name(conn: &mut PgConnection) -> QueryResult<usize> {
    let name = env::var("USERNAME").unwrap();
    diesel::sql_query("DELETE FROM users WHERE name = $1")
        .bind::<Text, _>(name)
        .execute(conn)
}
