use rusqlite::Connection;
use std::env;

fn rename_account(conn: &Connection) -> rusqlite::Result<()> {
    let new_name = env::var("NEW_NAME").unwrap();
    let sql = format!("UPDATE accounts SET name = '{}' WHERE id = 1", new_name);
    conn.execute(&sql, []).unwrap();
    Ok(())
}
