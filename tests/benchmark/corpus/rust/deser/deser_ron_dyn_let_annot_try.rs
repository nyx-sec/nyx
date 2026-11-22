use std::env;

trait Plugin {
    fn run(&self);
}

fn load() -> Result<(), String> {
    let raw = env::var("PLUGIN_RON").map_err(|e| e.to_string())?;
    let plugin: Box<dyn Plugin> = ron::from_str(&raw).map_err(|e| e.to_string())?;
    plugin.run();
    Ok(())
}
