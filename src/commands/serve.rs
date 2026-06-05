use crate::errors::NyxResult;
use crate::server::app::{AppState, ServerEvent, build_router};
use crate::server::jobs::JobManager;
use crate::server::security::LocalServerSecurity;
use crate::utils::config::Config;
use crate::utils::targets::{TargetTouch, remember_target};
use console::style;
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;

pub fn handle(
    path: &str,
    port: Option<u16>,
    host: Option<&str>,
    no_browser: bool,
    config_dir: &Path,
    database_dir: &Path,
    config: &Config,
) -> NyxResult<()> {
    let scan_root = Path::new(path).canonicalize()?;

    let requested_host = host
        .map(String::from)
        .unwrap_or_else(|| config.server.host.clone());
    let host = normalize_loopback_host(&requested_host)?;
    let port = port.unwrap_or(config.server.port);
    let open_browser = !no_browser && config.server.open_browser;
    let max_jobs = config.server.max_saved_runs as usize;
    let rayon_stack_size = config.performance.rayon_thread_stack_size;

    let (event_tx, _) = tokio::sync::broadcast::channel(64);
    let _ = remember_target(database_dir, &scan_root, TargetTouch::Seen);

    let addr = socket_addr(&host, port);

    eprintln!(
        "\n  {} Nyx web UI at {}\n",
        style("Serving").green().bold(),
        style(format!("http://{addr}")).cyan().underlined(),
    );
    eprintln!(
        "  Scan root: {}\n  Press {} to stop\n",
        style(scan_root.display()).dim(),
        style("Ctrl+C").bold(),
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| crate::errors::NyxError::Msg(format!("Failed to build tokio runtime: {e}")))?;

    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| crate::errors::NyxError::Msg(format!("Failed to bind {addr}: {e}")))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| crate::errors::NyxError::Msg(format!("Failed to read local addr: {e}")))?;
        let display_host = display_host(&host);
        let url = format!("http://{}:{}", display_host, local_addr.port());
        let security = LocalServerSecurity::new(local_addr.port());

        let state = AppState {
            scan_root: Arc::new(RwLock::new(scan_root.clone())),
            config_dir: config_dir.to_path_buf(),
            database_dir: database_dir.to_path_buf(),
            security,
            config: Arc::new(RwLock::new(config.clone())),
            job_manager: Arc::new(JobManager::new(max_jobs, rayon_stack_size)),
            event_tx: event_tx.clone(),
            db_pools: Arc::new(RwLock::new(std::collections::HashMap::new())),
            findings_cache: Arc::new(RwLock::new(None)),
        };
        let _ = state.db_pool_for(&scan_root);

        // Invalidate the findings cache whenever a scan finishes so the next
        // request rebuilds against fresh diags. The next-request rebuild keeps
        // this hot-path simple, we only clear the slot here, never recompute.
        let cache_for_invalidate = Arc::clone(&state.findings_cache);
        let mut event_rx = event_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(ServerEvent::ScanCompleted { .. } | ServerEvent::ScanFailed { .. }) => {
                        *cache_for_invalidate.write() = None;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let router = build_router(state);

        if open_browser {
            open_browser_url(&url);
        }

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| crate::errors::NyxError::Msg(format!("Server error: {e}")))?;

        eprintln!("\n  {} Server stopped.", style("Done.").green().bold());
        Ok(())
    })
}

fn normalize_loopback_host(host: &str) -> NyxResult<String> {
    let normalized = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    match normalized.as_str() {
        "localhost" | "127.0.0.1" | "::1" => Ok(normalized),
        _ => Err(crate::errors::NyxError::Msg(format!(
            "Nyx serve only binds to loopback addresses; refused host '{host}'"
        ))),
    }
}

fn socket_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn display_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for Ctrl+C");
    eprintln!("\n  Shutting down...");
    // SSE connections block graceful shutdown indefinitely.
    // Use a raw OS thread to force exit, tokio tasks may not
    // run reliably during shutdown.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(250));
        std::process::exit(0);
    });
}

fn open_browser_url(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn();
    }
}
