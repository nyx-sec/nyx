/// SQL injection — negative fixture.
///
/// Safe function: uses parameterized query (rusqlite params![]).
/// Expected verdict: NotConfirmed (no injection possible; oracle cannot fire).
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

    // Safe: parameterized query — payload cannot escape the literal binding.
    let mut stmt = conn
        .prepare("SELECT name FROM users WHERE name=?1")
        .expect("prepare");

    // Sink reached via safe parameterized path; sentinel fires but oracle will not.
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let _ = stmt
        .query_map(rusqlite::params![payload], |row| row.get::<_, String>(0))
        .map(|rows| {
            for name in rows.flatten() {
                println!("{}", name);
            }
        });
}
