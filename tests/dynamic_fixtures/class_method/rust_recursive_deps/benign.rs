// Benign control for recursive Rust class-method receiver construction.

pub struct CommandRunner;

impl CommandRunner {
    pub fn run(&self, input: &str) -> String {
        let out = std::process::Command::new("true")
            .arg(input)
            .output()
            .expect("exec");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

pub struct UserService {
    pub runner: CommandRunner,
}

impl UserService {
    pub fn run(&self, input: &str) -> String {
        self.runner.run(input)
    }
}
