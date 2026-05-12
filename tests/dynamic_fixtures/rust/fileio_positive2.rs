/// File I/O — second positive fixture.
///
/// Variant: uses std::fs::File::open instead of read_to_string; path constructed
/// from a base directory and user-supplied component (still traversable).
/// Expected verdict: Confirmed (payload "../../../../etc/passwd" reaches /etc/passwd).
/// Cap: FILE_IO  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    use std::io::Read;

    // Vulnerable: path joins base with user input without canonicalization.
    let path = format!("/var/data/{}", payload);

    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    match std::fs::File::open(&path) {
        Ok(mut f) => {
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            print!("{}", buf);
        }
        Err(e) => eprintln!("Error opening {}: {}", path, e),
    }
}
