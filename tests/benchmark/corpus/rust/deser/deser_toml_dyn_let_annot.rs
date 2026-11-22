use std::env;

trait Plugin {
    fn run(&self);
}

fn main() {
    let raw = env::var("PLUGIN_TOML").unwrap();
    let plugin: Box<dyn Plugin> = toml::from_str(&raw).unwrap();
    plugin.run();
}
