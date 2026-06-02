use clap::Parser;
use console::style;
use directories::ProjectDirs;
use nyx_scanner::cli::Cli;
use nyx_scanner::commands;
use nyx_scanner::errors::NyxResult;
use nyx_scanner::fmt;
use nyx_scanner::utils::Config;
use std::fs;
use std::time::Instant;
use tracing_subscriber::fmt::time;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Registry, fmt as tracing_fmt};

fn init_tracing(quiet: bool) {
    let filter = if quiet {
        EnvFilter::new("off")
    } else {
        EnvFilter::from_default_env()
    };

    let fmt_layer = tracing_fmt::layer()
        .pretty()
        .with_writer(std::io::stderr)
        .with_thread_ids(true)
        .with_timer(time::UtcTime::rfc_3339());

    Registry::default().with(filter).with(fmt_layer).init();
}

fn main() -> NyxResult<()> {
    let now = Instant::now();

    if std::env::args().count() == 1 {
        eprint!("{}", fmt::render_welcome());
        return Ok(());
    }

    let cli = Cli::parse();

    let proj_dirs =
        ProjectDirs::from("", "", "nyx").ok_or("Unable to determine project directories")?;

    // todo: check if we want to actually build a config file, maybe some environments will not want to have anything written
    let config_dir = proj_dirs.config_dir();
    fs::create_dir_all(config_dir)?;

    let database_dir = proj_dirs.data_local_dir();
    fs::create_dir_all(database_dir)?;

    let (mut config, config_note) = Config::load(config_dir)?;

    let explicit_quiet = config.output.quiet || cli.command.quiet_requested();
    init_tracing(explicit_quiet);
    tracing::debug!("CLI starting up");

    rayon::ThreadPoolBuilder::new()
        .stack_size(config.performance.rayon_thread_stack_size)
        .build_global()
        .expect("set rayon stack size");

    let is_serve = cli.command.is_serve();
    let is_info = cli.command.is_informational();
    let quiet = explicit_quiet || cli.command.is_structured_output(&config);

    // Print config note before scanning (human-readable mode only).  Pure
    // informational commands suppress it too, their output is usually
    // piped or grepped and the preamble is noise.
    if let Some(note) = config_note.filter(|_| !quiet && !is_info) {
        eprint!("{note}");
    }

    commands::handle_command(cli.command, database_dir, config_dir, &mut config)?;

    // "Finished in" is useful for long scans but pure noise on fast paths
    // (small repos, `index status`, `clean` etc.).  Suppress it under a
    // second; users who care about precise timings can use `time`/`hyperfine`.
    let elapsed = now.elapsed();
    if !quiet && !is_serve && !is_info && elapsed.as_secs_f32() >= 1.0 {
        eprintln!(
            "{} in {:.3}s.",
            style("Finished").green().bold(),
            elapsed.as_secs_f32()
        );
    }
    Ok(())
}
