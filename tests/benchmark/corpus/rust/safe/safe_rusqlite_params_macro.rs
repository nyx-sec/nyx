use rusqlite::{params, Connection};
use std::env;

fn rename_account() -> rusqlite::Result<()> {
    let conn = Connection::open("app.db")?;
    let new_name = env::var("NEW_NAME").unwrap();
    conn.execute(
        "UPDATE accounts SET name = ?1 WHERE id = 1",
        params![new_name],
    )
    .unwrap();
    Ok(())
}
