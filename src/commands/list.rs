use crate::errors::NyxResult;
use bytesize::ByteSize;
use console::style;
use std::fs;

pub fn handle(verbose: bool, database_dir: &std::path::Path) -> NyxResult<()> {
    println!("{}", style("Indexed projects").bold());

    if !database_dir.exists() {
        println!("  {}", style("(none)").dim());
        std::process::exit(0);
    }

    let mut entries: Vec<_> = fs::read_dir(database_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("sqlite"))
        .collect();
    entries.sort();

    if entries.is_empty() {
        println!("  {}", style("(none)").dim());
        std::process::exit(0);
    }

    for path in &entries {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        if verbose {
            let meta = fs::metadata(path)?;
            let size = ByteSize::b(meta.len());
            let mtime = crate::utils::time::local_datetime(meta.modified()?);
            println!(
                "  {} {} {}",
                style(name).white().bold(),
                style(format!("({size})")).dim(),
                style(format!("· {mtime}")).dim()
            );
            println!("    {}", style(path.display()).dim().underlined());
        } else {
            println!("  {}", style(name).white().bold());
        }
    }

    println!();
    println!("{}", style(format!("{} project(s)", entries.len())).dim());

    std::process::exit(0);
}
