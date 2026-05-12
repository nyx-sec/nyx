/// SQL injection — positive fixture.
///
/// Vulnerable function: directly concatenates user input into SQL.
/// Expected verdict: Confirmed (UNION payload causes "NYX_SQL_CONFIRMED" in output).
/// Cap: SQL_QUERY  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    use rusqlite::Connection;

    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(
        "CREATE TABLE users (id INTEGER, name TEXT);\
         INSERT INTO users VALUES (1, 'alice');\
         INSERT INTO users VALUES (2, 'bob');",
    )
    .expect("setup schema");

    // Vulnerable: direct string concatenation into SQL.
    let query = format!("SELECT name FROM users WHERE name='{}'", payload);

    // Sentinel: the sink (conn.prepare) is reachable with tainted input.
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    match conn.prepare(&query) {
        Ok(mut stmt) => {
            let _ = stmt.query_map([], |row| row.get::<_, String>(0)).map(|rows| {
                for name in rows.flatten() {
                    println!("{}", name);
                }
            });
        }
        Err(e) => {
            // Error-based: print query on failure (oracle can detect via query echo).
            println!("DB query: {}", query);
            println!("DB error: {}", e);
        }
    }
}
