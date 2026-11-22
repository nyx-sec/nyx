use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Config {
    listen: String,
    workers: usize,
}

fn load_config() -> Config {
    let text = fs::read_to_string("/etc/app/app.toml").unwrap();
    let cfg: Config = toml::from_str(&text).unwrap();
    cfg
}
