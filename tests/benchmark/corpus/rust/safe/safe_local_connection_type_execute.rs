use std::env;

struct Connection {
    log: Vec<String>,
}

impl Connection {
    fn execute(&mut self, line: &str) {
        self.log.push(line.to_string());
    }
}

struct Recorder {
    conn: Connection,
}

impl Recorder {
    fn record(&mut self) {
        let name = env::var("ITEM_NAME").unwrap();
        self.conn.execute(&format!("DELETE FROM items WHERE name = '{}'", name));
    }
}
