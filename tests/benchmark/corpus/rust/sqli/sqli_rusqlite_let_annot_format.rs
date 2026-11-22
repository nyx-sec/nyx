use rusqlite::Connection;
use std::env;

fn open_db() -> Connection {
    Connection::open("app.db").unwrap()
}

fn purge() {
    let name = env::var("ITEM_NAME").unwrap();
    let conn: Connection = open_db();
    conn.execute(&format!("DELETE FROM items WHERE name = '{}'", name), [])
        .unwrap();
}
