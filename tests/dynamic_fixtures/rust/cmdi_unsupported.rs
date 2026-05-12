/// Command injection — unsupported entry-kind fixture.
///
/// Vulnerable logic lives inside a struct method. The test creates a Diag
/// with an unsupported entry kind so `HarnessSpec::from_finding` returns
/// `Err(UnsupportedReason::EntryKindUnsupported)`.
///
/// Expected verdict: Unsupported(EntryKindUnsupported)
/// Cap: CODE_EXEC
pub struct ShellRunner;

impl ShellRunner {
    pub fn execute(&self, user_cmd: &str) -> Option<String> {
        use std::process::Command;
        let cmd = format!("run {}", user_cmd);
        Command::new("sh")
            .args(["-c", &cmd])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    }
}
