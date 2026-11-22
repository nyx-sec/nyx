use rusqlite::Connection;
use std::env;

struct Audit {
    entries: Vec<String>,
}

impl Audit {
    fn execute(&mut self, line: &str) {
        self.entries.push(line.to_string());
    }
}

struct Store {
    conn: Connection,
    audit: Audit,
}

impl Store {
    fn purge(&mut self) {
        let name = env::var("ITEM_NAME").unwrap();
        self.audit.execute(&format!("purge {}", name));
        self.conn.execute("DELETE FROM items", []).unwrap();
    }
}
