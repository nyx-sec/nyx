#[repr(u16)]
pub enum Wide {
    A,
    B,
}

pub enum Explicit {
    Big = 300,
}

const TOO_BIG: usize = 70000;

pub fn bad(v: &Vec<String>, n: u64, x: i64) -> (u16, u8, i16) {
    (v.len() as u16, n as u8, x as i16)
}

pub fn more(a: Wide, hi: u32) -> (u8, u8, u16, u8, u8) {
    (
        Wide::A as u8,
        Explicit::Big as u8,
        TOO_BIG as u16,
        (hi & 0x1FF) as u8,
        300 as u8,
    )
}
