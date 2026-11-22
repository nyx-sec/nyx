use rusqlite::Connection;
use std::env;

struct Store {
    conn: Connection,
}

impl Store {
    fn purge(&self) {
        let name = env::var("ITEM_NAME").unwrap();
        self.conn
            .execute("DELETE FROM items WHERE name = ?1", [name])
            .unwrap();
    }
}
