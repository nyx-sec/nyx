use axum::extract::Query;
use std::collections::HashMap;

struct Config {}

fn load(Query(q): Query<HashMap<String, String>>) -> Result<(), Box<dyn std::error::Error>> {
    let s = q.get("a").unwrap().clone();
    let cfg: Result<Config, Box<dyn std::error::Error>> = toml::from_str(&s).map_err(Into::into);
    let _ = cfg;
    Ok(())
}
