// Module-level `const` scalar binds the first arg of a Command::new call.
// Without file-level scalar recognition the SSA path treats COMMAND as a
// free identifier and the structural rule over-fires.

use std::process::Command;

const COMMAND: &str = "ls";
const ARG_COUNT: i32 = 2;

pub fn run() {
    let _ = Command::new(COMMAND).output();
}
