// Phase 19 (Track M.1) — class-method vuln fixture for Rust.
//
// `UserService::run` shells out with a concatenated `sh -c <input>`,
// classic OS command injection.  Derives Default so the harness can
// build the receiver without manual stubbing.

#[derive(Default)]
pub struct UserService;

impl UserService {
    pub fn run(&self, input: &str) -> String {
        // SINK: tainted input → shell -c
        let cmd = format!("echo {}", input);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .expect("exec");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}
