use std::env;

trait Plugin {
    fn run(&self);
}

fn main() {
    let raw = env::var("PLUGIN_TOML").unwrap();
    let plugin = toml::from_str::<Box<dyn Plugin>>(&raw).unwrap();
    plugin.run();
}
