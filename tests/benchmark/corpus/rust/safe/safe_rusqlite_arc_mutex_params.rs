use rusqlite::{params, Connection};
use std::env;
use std::sync::{Arc, Mutex};

struct Store {
    pool: Arc<Mutex<Connection>>,
}

impl Store {
    fn purge(&self) {
        let name = env::var("ITEM_NAME").unwrap();
        let conn = self.pool.lock().unwrap();
        conn.execute("DELETE FROM items WHERE name = ?1", params![name])
            .unwrap();
    }
}
