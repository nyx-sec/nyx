/// File I/O — negative fixture.
///
/// Safe function: reads from a fixed path; user input is only used as a search
/// term within file contents, not as the file path itself.
/// Expected verdict: NotConfirmed.
/// Cap: FILE_IO  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Safe: path is hard-coded; payload cannot influence which file is read.
    let fixed_path = "/tmp/nyx_safe_file_does_not_exist";

    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    match std::fs::read_to_string(fixed_path) {
        Ok(contents) => {
            // Only use payload as a filter, not as a path.
            for line in contents.lines() {
                if line.contains(payload) {
                    println!("{}", line);
                }
            }
        }
        Err(_) => {
            println!("file not found (expected in test)");
        }
    }
}
