/// SQL injection — unsupported entry-kind fixture.
///
/// The vulnerable logic lives inside a struct method. The test creates a Diag
/// with an unsupported entry kind, so `HarnessSpec::from_finding` returns
/// `Err(UnsupportedReason::EntryKindUnsupported)`.
///
/// Expected verdict: Unsupported(EntryKindUnsupported)
/// Cap: SQL_QUERY
pub struct UserRepository;

impl UserRepository {
    pub fn find_user(&self, name: &str) -> Vec<String> {
        use rusqlite::Connection;
        let conn = Connection::open_in_memory().expect("open db");
        let query = format!("SELECT name FROM users WHERE name='{}'", name);
        match conn.prepare(&query) {
            Ok(mut stmt) => stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map(|rows| rows.flatten().collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        }
    }
}
