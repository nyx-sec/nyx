use rusqlite::Connection;
use std::env;
use std::sync::{Arc, Mutex};

fn purge(pool: &Arc<Mutex<Connection>>) {
    let name = env::var("ITEM_NAME").unwrap();
    let conn = pool.lock().unwrap();
    conn.execute(&format!("DELETE FROM items WHERE name = '{}'", name), [])
        .unwrap();
}
