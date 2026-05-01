pub mod clean;
pub mod config;
pub mod index;
pub mod list;
pub mod scan;
#[cfg(feature = "serve")]
pub mod serve;

use crate::cli::{Commands, EngineProfile, IndexMode, ScanMode};
use crate::errors::NyxResult;
use crate::patterns::{Severity, SeverityFilter};
use crate::utils::config::{AnalysisMode, Config};
use std::path::Path;

pub fn handle_command(
    command: Commands,
    database_dir: &Path,
    config_dir: &Path,
    config: &mut Config,
) -> NyxResult<()> {
    // Resolve engine options once for the whole process.  Scan overlays CLI
    // flags below; other subcommands use the config values verbatim.  The
    // install is a no-op after the first call, so Scan's overlay must happen
    // before we reach this point for its own call path, we delay the install
    // to the Scan arm and gate non-scan commands behind a fallback install of
    // the bare config values.
    let install_from_config = |config: &Config| {
        if config.analysis.engine.parse_timeout_ms == 0 {
            tracing::warn!(
                "parse_timeout_ms = 0 disables tree-sitter parse timeout entirely; \
                 this is unsafe for untrusted input."
            );
        }
        let _ = crate::utils::analysis_options::install(config.analysis.engine);
        let _ = crate::utils::detector_options::install(config.detectors.clone());
    };

    match command {
        Commands::Scan {
            path,
            index,
            format,
            severity,
            mode,
            profile,
            engine_profile,
            explain_engine,
            all_targets,
            keep_nonprod_severity,
            quiet,
            fail_on,
            no_state,
            no_rank,
            show_suppressed,
            show_all,
            include_quality,
            max_low,
            max_low_per_file,
            max_low_per_rule,
            rollup_examples,
            show_instances,
            min_score,
            min_confidence,
            require_converged,
            // Analysis engine toggles
            constraint_solving,
            no_constraint_solving,
            abstract_interp,
            no_abstract_interp,
            context_sensitive,
            no_context_sensitive,
            symex,
            no_symex,
            cross_file_symex,
            no_cross_file_symex,
            symex_interproc,
            no_symex_interproc,
            smt,
            no_smt,
            backwards_analysis,
            no_backwards_analysis,
            parse_timeout_ms,
            max_origins,
            max_pointsto,
            // Deprecated aliases
            no_index,
            rebuild_index,
            high_only,
            ast_only,
            cfg_only,
        } => {
            // ── Apply profile first (CLI flags override after) ──────────
            if let Some(ref name) = profile {
                config.apply_profile(name)?;
            }

            // ── Resolve deprecated aliases ──────────────────────────────
            // Each alias still works but emits a one-line stderr nudge so
            // users learn the new flag.  Suppressed under --quiet and
            // structured output formats so machine pipelines stay clean.
            use crate::cli::OutputFormat;
            let effective_format = format.unwrap_or(config.output.default_format);
            let structured = matches!(effective_format, OutputFormat::Json | OutputFormat::Sarif);
            let suppress_warnings = quiet || config.output.quiet || structured;
            let warn_dep = |old: &str, new: &str| {
                if !suppress_warnings {
                    eprintln!(
                        "{}: {} is deprecated; use {} instead.",
                        console::style("warn").yellow().bold(),
                        console::style(old).bold(),
                        console::style(new).bold()
                    );
                }
            };

            // Index mode: explicit --index wins, then deprecated flags
            let effective_index = if no_index {
                warn_dep("--no-index", "--index off");
                IndexMode::Off
            } else if rebuild_index {
                warn_dep("--rebuild-index", "--index rebuild");
                IndexMode::Rebuild
            } else {
                index
            };

            // Analysis mode: explicit --mode wins, then deprecated flags
            let effective_mode = if ast_only {
                warn_dep("--ast-only", "--mode ast");
                ScanMode::Ast
            } else if cfg_only {
                warn_dep("--cfg-only", "--mode cfg");
                ScanMode::Cfg
            } else if all_targets {
                warn_dep("--all-targets", "--mode full");
                ScanMode::Full
            } else {
                mode
            };

            // Severity filter: explicit --severity wins, then --high-only
            let severity_filter = if let Some(ref expr) = severity {
                Some(SeverityFilter::parse(expr).map_err(|e| {
                    crate::errors::NyxError::Msg(format!("invalid --severity expression: {e}"))
                })?)
            } else if high_only {
                warn_dep("--high-only", "--severity HIGH");
                Some(SeverityFilter::parse("HIGH").unwrap())
            } else {
                None
            };

            // Fail-on threshold
            let fail_on_sev = if let Some(ref expr) = fail_on {
                Some(expr.trim().parse::<Severity>().map_err(|e| {
                    crate::errors::NyxError::Msg(format!("invalid --fail-on value: {e}"))
                })?)
            } else {
                None
            };

            // ── Apply to config ─────────────────────────────────────────

            match effective_mode {
                ScanMode::Full => config.scanner.mode = AnalysisMode::Full,
                ScanMode::Ast => config.scanner.mode = AnalysisMode::Ast,
                ScanMode::Cfg => config.scanner.mode = AnalysisMode::Cfg,
                ScanMode::Taint => config.scanner.mode = AnalysisMode::Taint,
            }

            if keep_nonprod_severity {
                config.scanner.include_nonprod = true;
            }

            if quiet {
                config.output.quiet = true;
            }

            if no_state {
                config.scanner.enable_state_analysis = false;
            }

            if no_rank {
                config.output.attack_surface_ranking = false;
            }

            // Min-score: CLI wins, then config
            if let Some(s) = min_score {
                config.output.min_score = Some(s);
            }

            // Min-confidence: CLI wins, then config
            if let Some(ref expr) = min_confidence {
                config.output.min_confidence =
                    Some(expr.parse::<crate::evidence::Confidence>().map_err(|e| {
                        crate::errors::NyxError::Msg(format!("invalid --min-confidence value: {e}"))
                    })?);
            }

            if require_converged {
                config.output.require_converged = true;
            }

            if show_all {
                config.output.show_all = true;
            }
            if include_quality {
                config.output.include_quality = true;
            }
            // CLI values override config defaults (clap provides defaults)
            config.output.max_low = max_low;
            config.output.max_low_per_file = max_low_per_file;
            config.output.max_low_per_rule = max_low_per_rule;
            config.output.rollup_examples = rollup_examples;

            // ── Analysis engine toggles: resolve CLI → config ───────────
            // Each pair is a tri-state (flag set ⇒ true, no-flag set ⇒ false,
            // neither ⇒ inherit config default).
            //
            // Application order: profile first (wholesale reset), then
            // individual flags layered on top so users can mix a profile
            // with a targeted override (e.g. `--engine-profile fast
            // --backwards-analysis`).
            let mut engine = config.analysis.engine;
            if let Some(ref prof) = engine_profile {
                engine = prof.apply(engine);
            }
            if constraint_solving {
                engine.constraint_solving = true;
            }
            if no_constraint_solving {
                engine.constraint_solving = false;
            }
            if abstract_interp {
                engine.abstract_interpretation = true;
            }
            if no_abstract_interp {
                engine.abstract_interpretation = false;
            }
            if context_sensitive {
                engine.context_sensitive = true;
            }
            if no_context_sensitive {
                engine.context_sensitive = false;
            }
            if symex {
                engine.symex.enabled = true;
            }
            if no_symex {
                engine.symex.enabled = false;
            }
            if cross_file_symex {
                engine.symex.cross_file = true;
            }
            if no_cross_file_symex {
                engine.symex.cross_file = false;
            }
            if symex_interproc {
                engine.symex.interprocedural = true;
            }
            if no_symex_interproc {
                engine.symex.interprocedural = false;
            }
            if smt {
                engine.symex.smt = true;
            }
            if no_smt {
                engine.symex.smt = false;
            }
            if backwards_analysis {
                engine.backwards_analysis = true;
            }
            if no_backwards_analysis {
                engine.backwards_analysis = false;
            }
            if let Some(ms) = parse_timeout_ms {
                engine.parse_timeout_ms = ms;
            }
            if let Some(n) = max_origins {
                engine.max_origins = n.max(crate::utils::analysis_options::MIN_MAX_ORIGINS);
            }
            if let Some(n) = max_pointsto {
                engine.max_pointsto = n.max(crate::utils::analysis_options::MIN_MAX_POINTSTO);
            }
            config.analysis.engine = engine;
            if engine.parse_timeout_ms == 0 {
                tracing::warn!(
                    "parse_timeout_ms = 0 disables tree-sitter parse timeout entirely; \
                     this is unsafe for untrusted input."
                );
            }
            if !crate::utils::analysis_options::install(engine) {
                tracing::warn!(
                    "analysis-engine runtime already installed; CLI engine flags ignored"
                );
            }
            // Detector knobs (currently `[detectors.data_exfil]`) are
            // resolved straight from config; no CLI overrides yet.
            let _ = crate::utils::detector_options::install(config.detectors.clone());

            // ── --explain-engine: print resolved config and exit ────────
            if explain_engine {
                print_engine_explanation(config, engine_profile);
                return Ok(());
            }

            let effective_format = format.unwrap_or(config.output.default_format);

            scan::handle(
                &path,
                effective_index,
                effective_format,
                severity_filter,
                fail_on_sev,
                show_suppressed,
                show_instances.as_deref(),
                database_dir,
                config,
            )?;
        }
        Commands::Index { action } => {
            install_from_config(config);
            index::handle(action, database_dir, config)?;
        }
        Commands::List { verbose } => {
            list::handle(verbose, database_dir)?;
        }
        Commands::Clean { project, all } => {
            clean::handle(project, all, database_dir)?;
        }
        Commands::Config { action } => {
            use crate::cli::ConfigAction;
            match action {
                ConfigAction::Show { all } => self::config::show(config, all)?,
                ConfigAction::Path => self::config::path(config_dir)?,
                ConfigAction::AddRule {
                    lang,
                    matcher,
                    kind,
                    cap,
                } => self::config::add_rule(config_dir, &lang, &matcher, &kind, &cap)?,
                ConfigAction::AddTerminator { lang, name } => {
                    self::config::add_terminator(config_dir, &lang, &name)?
                }
            }
        }
        Commands::Serve {
            path,
            port,
            host,
            no_browser,
        } => {
            install_from_config(config);
            #[cfg(feature = "serve")]
            {
                serve::handle(
                    &path,
                    port,
                    host.as_deref(),
                    no_browser,
                    config_dir,
                    database_dir,
                    config,
                )?;
            }
            #[cfg(not(feature = "serve"))]
            {
                let _ = (path, port, host, no_browser);
                return Err(crate::errors::NyxError::Msg(
                    "The `serve` feature is not enabled. Rebuild with `cargo build --features serve`.".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Pretty-print the effective analysis-engine configuration for
/// `nyx scan --explain-engine`.  Writes to stdout so it composes with
/// standard shell redirection and process substitution.
fn print_engine_explanation(config: &Config, engine_profile: Option<EngineProfile>) {
    use console::style;

    // Plain-text on/off, padded to 3 chars so the trailing column aligns
    // regardless of which value is rendered.  Colour is layered on top ,
    // the visible width stays 3 characters because `console::style` emits
    // zero-width ANSI codes (and nothing at all when NO_COLOR is set).
    fn onoff(b: bool) -> String {
        if b {
            style("on ").green().to_string()
        } else {
            style("off").red().dim().to_string()
        }
    }

    let engine = config.analysis.engine;
    let scanner = &config.scanner;
    let profile_label = engine_profile
        .map(|p| p.to_string())
        .unwrap_or_else(|| "(none, using config defaults)".to_string());
    let smt_compiled = cfg!(feature = "smt");
    let pipeline_on = matches!(
        config.scanner.mode,
        AnalysisMode::Full | AnalysisMode::Cfg | AnalysisMode::Taint
    );

    // Layout: 2sp + label (left-aligned, 24w) + space + value + 3sp + flag info.
    // Label width 24 fits the longest entry ("Abstract interpretation:") with
    // a single trailing space before the value column.  Numeric rows reuse
    // the same alignment so the value column is consistent across sections.
    let row_flag = |label: &str, on: bool, flags: &str| {
        println!(
            "    {:<24} {}   {}",
            format!("{label}:"),
            onoff(on),
            style(flags).dim()
        );
    };
    let row_plain = |label: &str, value: &str| {
        println!("    {:<24} {}", format!("{label}:"), value);
    };
    let row_num = |label: &str, value: String, flags: &str| {
        println!(
            "    {:<24} {:<10} {}",
            format!("{label}:"),
            value,
            style(flags).dim()
        );
    };
    let section = |title: &str| {
        println!();
        println!("  {}", style(title).cyan().bold());
    };

    println!("{}", style("Effective engine configuration").white().bold());
    println!(
        "    {:<24} {}",
        "Engine profile:",
        style(&profile_label).bold()
    );

    section("Pipeline");
    row_plain("AST patterns", &onoff(true));
    row_plain("CFG construction", &onoff(pipeline_on));
    row_plain("CFG analysis", &onoff(pipeline_on));
    row_plain("Taint (SSA)", &onoff(pipeline_on));
    row_plain("State analysis", &onoff(scanner.enable_state_analysis));
    row_plain("Auth analysis", &onoff(scanner.enable_auth_analysis));

    section("Engine toggles");
    row_flag(
        "Abstract interpretation",
        engine.abstract_interpretation,
        "--abstract-interp / NYX_ABSTRACT_INTERP",
    );
    row_flag(
        "Context sensitivity",
        engine.context_sensitive,
        "--context-sensitive / NYX_CONTEXT_SENSITIVE (k=1)",
    );
    row_flag(
        "Constraint solving",
        engine.constraint_solving,
        "--constraint-solving / NYX_CONSTRAINT",
    );
    // Backwards-taint label and value column kept exact-width-compatible
    // with the legacy format so external scripts grepping for
    // "Backwards taint:         on" continue to match.  The label slot is
    // 24 chars + 1 space → column 25, which lines up with that legacy
    // 9-space gap after "Backwards taint:" (16 chars).
    row_flag(
        "Backwards taint",
        engine.backwards_analysis,
        "--backwards-analysis / NYX_BACKWARDS",
    );

    section("Symbolic execution");
    row_flag("Symex", engine.symex.enabled, "--symex / NYX_SYMEX");
    row_flag(
        "Cross-file symex",
        engine.symex.cross_file,
        "--cross-file-symex / NYX_CROSS_FILE_SYMEX",
    );
    row_flag(
        "Interproc symex",
        engine.symex.interprocedural,
        "--symex-interproc / NYX_SYMEX_INTERPROC",
    );
    let smt_note = if smt_compiled {
        "--smt"
    } else {
        "--smt (this binary built without `smt` feature)"
    };
    row_flag("SMT (Z3)", engine.symex.smt && smt_compiled, smt_note);

    section("Limits");
    row_num(
        "Parse timeout",
        format!("{} ms", engine.parse_timeout_ms),
        "--parse-timeout-ms / NYX_PARSE_TIMEOUT_MS (0 disables)",
    );
    row_num(
        "Max taint origins",
        engine.max_origins.to_string(),
        "--max-origins / NYX_MAX_ORIGINS (per-lattice-value cap)",
    );
    row_num(
        "Max points-to set",
        engine.max_pointsto.to_string(),
        "--max-pointsto / NYX_MAX_POINTSTO (per-variable heap cap)",
    );
    println!();
}
