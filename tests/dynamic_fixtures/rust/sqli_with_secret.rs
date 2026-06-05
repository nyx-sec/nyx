/// SQL injection fixture — same vulnerability as sqli_positive, placed in a
/// directory that contains a secrets file (.env with AWS key).
///
/// The test verifies that the AWS key is redacted from outcome.json / telemetry
/// and never appears in any repro artifact after verification.
///
/// Expected verdict: Confirmed (same oracle as sqli_positive)
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

    let query = format!("SELECT name FROM users WHERE name='{}'", payload);

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
            println!("DB query: {}", query);
            println!("DB error: {}", e);
        }
    }
}
