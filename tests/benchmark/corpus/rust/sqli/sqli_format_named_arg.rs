use std::env;

mod rusqlite {
    pub struct Connection;
    pub struct PreparedStmt;
    impl Connection {
        pub fn open(_path: &str) -> Result<Connection, String> {
            Ok(Connection)
        }
        pub fn prepare(&self, _sql: &str) -> Result<PreparedStmt, String> {
            Ok(PreparedStmt)
        }
    }
}

fn main() -> Result<(), String> {
    let user = env::var("USERNAME").unwrap();
    let conn = rusqlite::Connection::open("app.db").unwrap();
    // Rust 1.58+ named-arg capture: `{user}` reads the local
    // tainted variable directly.  Without format-string-named-arg
    // lifting, taint would stop at the macro boundary and miss the
    // SQL injection.  Regression guard for that engine fix.
    let query = format!("SELECT * FROM accounts WHERE name = '{user}'");
    conn.prepare(&query)?;
    Ok(())
}
