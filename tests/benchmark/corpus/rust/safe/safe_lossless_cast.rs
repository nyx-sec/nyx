#[repr(u8)]
pub enum Operation {
    Addition,
    Deletion,
}

const MAX_DISTANCE: usize = 8;

pub fn tag(buf: &mut Vec<u8>) {
    buf.push(Operation::Addition as u8);
}

pub fn low_half(absolute: u32) -> u16 {
    (absolute & 0xFFFF) as u16
}

pub fn limits(a: u32, b: u32) -> (u8, u8) {
    (MAX_DISTANCE as u8, (a == b) as u8)
}
