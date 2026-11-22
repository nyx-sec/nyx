use rusqlite::Connection;
use std::env;

struct Store {
    db: Connection,
}

impl Store {
    fn lookup(&self) -> i64 {
        let name = env::var("ITEM_NAME").unwrap();
        self.db
            .query_row(
                "SELECT id FROM items WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap()
    }
}
