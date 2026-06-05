// Rust class-method fixture whose receiver has same-file dependencies
// but no Default or new() constructor.

pub struct CommandRunner;

impl CommandRunner {
    pub fn run(&self, input: &str) -> String {
        let cmd = format!("true {}", input);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
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
