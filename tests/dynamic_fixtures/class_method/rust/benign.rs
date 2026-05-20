// Phase 19 (Track M.1) — class-method benign control for Rust.

#[derive(Default)]
pub struct UserService;

impl UserService {
    pub fn run(&self, input: &str) -> String {
        let out = std::process::Command::new("/bin/echo")
            .arg(input)
            .output()
            .expect("exec");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}
