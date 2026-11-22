#[repr(u8)]
pub enum Operation {
    Addition,
    Deletion,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Kind {
    A,
    B,
}

impl Kind {
    pub const fn repr(&self) -> u8 {
        *self as u8
    }
    pub const fn first() -> u8 {
        Self::A as u8
    }
}

pub enum Plain {
    One,
    Two,
}

const MAX_DISTANCE: usize = 8;

pub fn tag(buf: &mut Vec<u8>) {
    buf.push(Operation::Addition as u8);
    if buf[0] == Operation::Deletion as u8 {
        buf.clear();
    }
    buf.push(Plain::Two as u8);
}

pub fn low_half(absolute: u32) -> u16 {
    (absolute & 0xFFFF) as u16
}

pub fn limits(a: u32, b: u32) -> (u8, u8, u8, u16) {
    (MAX_DISTANCE as u8, 200 as u8, (a == b) as u8, b'a' as u16)
}
