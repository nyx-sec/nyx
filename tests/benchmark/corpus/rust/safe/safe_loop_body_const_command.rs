// The `loop` header evaluates nothing.  The tainted `name` is only printed;
// the command run in the body is a constant.
use std::env;
use std::process::Command;

fn main() {
    let name = env::var("NAME").unwrap_or_default();
    loop {
        let _ = Command::new("ls").status();
        println!("{}", name);
        break;
    }
}
