use std::env;

trait Plugin {
    fn run(&self);
}

fn main() {
    let raw = env::var("PLUGIN_TOML").unwrap();
    let plugin: Result<Box<dyn Plugin>, toml::de::Error> = toml::from_str(&raw);
    plugin.unwrap().run();
}
