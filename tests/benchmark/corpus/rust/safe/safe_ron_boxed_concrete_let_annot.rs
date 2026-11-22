use serde::Deserialize;
use std::env;

#[derive(Deserialize)]
struct Settings {
    name: String,
}

fn load() -> Result<Box<Settings>, String> {
    let raw = env::var("SETTINGS_RON").map_err(|e| e.to_string())?;
    let settings: Box<Settings> = ron::from_str(&raw).map_err(|e| e.to_string())?;
    Ok(settings)
}
