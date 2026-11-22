pub fn encode(items: &Vec<String>, n: u64) -> (u16, u8) {
    (items.len() as u16, n as u8)
}
