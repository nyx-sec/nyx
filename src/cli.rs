//! Command-line interface definition via clap.
//!
//! Defines [`Cli`] (the top-level parser) and the [`Commands`] enum of
//! subcommands. Helpers on [`Commands`] answer routing questions the binary
//! needs without pattern-matching on specific arms: [`Commands::effective_format`],
//! [`Commands::is_structured_output`], [`Commands::is_serve`], and
//! [`Commands::is_informational`].

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "nyx")]
#[command(about = "A fast vulnerability scanner with project indexing")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Commands {
    /// Resolve the effective output format, using the config default when the
    /// CLI flag is omitted.
    pub fn effective_format(&self, config: &crate::utils::config::Config) -> OutputFormat {
        match self {
            Commands::Scan { format, .. } => format.unwrap_or(config.output.default_format),
            _ => OutputFormat::Console,
        }
    }

    /// Whether this command produces structured (machine-readable) output on
    /// stdout, meaning human status messages must be suppressed entirely.
    pub fn is_structured_output(&self, config: &crate::utils::config::Config) -> bool {
        let fmt = self.effective_format(config);
        matches!(self, Commands::Scan { .. })
            && (fmt == OutputFormat::Json || fmt == OutputFormat::Sarif)
    }

    /// Whether this is a long-running server command (skip timing output).
    pub fn is_serve(&self) -> bool {
        matches!(self, Commands::Serve { .. })
    }

    /// Pure read-only / informational commands that should run without the
    /// "note: Using …" config preamble or the trailing "Finished in …"
    /// timing line.  These commands' output is often piped or grepped; the
    /// surrounding chrome is noise.
    pub fn is_informational(&self) -> bool {
        match self {
            Commands::Scan { explain_engine, .. } => *explain_engine,
            Commands::List { .. } => true,
            Commands::Rules { .. } => true,
            Commands::Surface { .. } => true,
            Commands::Config { action } => {
                matches!(action, ConfigAction::Show { .. } | ConfigAction::Path)
            }
            Commands::Index { action } => matches!(action, IndexAction::Status { .. }),
            _ => false,
        }
    }
}

/// Output format for scan results.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Console,
    Json,
    Sarif,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Console => write!(f, "console"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
        }
    }
}

/// Index mode for scan operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
pub enum IndexMode {
    /// Use index if available, build if missing (default)
    #[default]
    Auto,
    /// Skip indexing entirely, scan filesystem directly
    Off,
    /// Force rebuild index before scanning
    Rebuild,
}

/// Analysis mode for scan operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
pub enum ScanMode {
    /// Run all analyses: AST analyses + CFG + taint (default)
    #[default]
    Full,
    /// Run AST analyses only (tree-sitter patterns + auth analysis; no CFG/taint/state)
    Ast,
    /// Run CFG structural analyses + taint only (no AST analyses)
    Cfg,
    /// Alias for cfg (CFG + taint analysis)
    Taint,
}

/// Output format for `nyx surface`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
pub enum SurfaceFormat {
    /// Indented tree, one entry-point per line, with reach summary.
    #[default]
    Text,
    /// Canonical SurfaceMap JSON, byte-identical to the SQLite payload.
    Json,
    /// Graphviz DOT source; pipe through `dot -Tsvg` to render.
    Dot,
    /// SVG produced by spawning the local `dot` binary on the DOT
    /// rendering.  Fails when graphviz is not installed.
    Svg,
}

impl std::fmt::Display for SurfaceFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SurfaceFormat::Text => write!(f, "text"),
            SurfaceFormat::Json => write!(f, "json"),
            SurfaceFormat::Dot => write!(f, "dot"),
            SurfaceFormat::Svg => write!(f, "svg"),
        }
    }
}

/// Engine-depth profile that sets the full stack of analysis toggles
/// in one shot.  Individual engine flags override the profile.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum EngineProfile {
    /// AST + CFG + basic taint. Disables symex, abstract-interp,
    /// context-sensitive, backwards-analysis, and SMT.
    Fast,
    /// AST + CFG + SSA taint + abstract interpretation + context-sensitive
    /// inlining. Disables symex, backwards-analysis, and SMT.
    /// (This is the default engine posture.)
    Balanced,
    /// Everything in `balanced` plus symex (including cross-file and
    /// interprocedural) and backwards-analysis. Still disables SMT
    /// (requires the `smt` cargo feature).
    Deep,
}

impl EngineProfile {
    /// Apply this profile to an `AnalysisOptions` struct, returning the
    /// new options.  Individual CLI flags are layered on top by the
    /// caller after this runs.
    pub fn apply(
        &self,
        mut opts: crate::utils::analysis_options::AnalysisOptions,
    ) -> crate::utils::analysis_options::AnalysisOptions {
        use crate::utils::analysis_options::SymexOptions;
        match self {
            EngineProfile::Fast => {
                opts.constraint_solving = false;
                opts.abstract_interpretation = false;
                opts.context_sensitive = false;
                opts.symex = SymexOptions {
                    enabled: false,
                    cross_file: false,
                    interprocedural: false,
                    smt: false,
                };
                opts.backwards_analysis = false;
            }
            EngineProfile::Balanced => {
                opts.constraint_solving = true;
                opts.abstract_interpretation = true;
                opts.context_sensitive = true;
                opts.symex = SymexOptions {
                    enabled: false,
                    cross_file: false,
                    interprocedural: false,
                    smt: false,
                };
                opts.backwards_analysis = false;
            }
            EngineProfile::Deep => {
                opts.constraint_solving = true;
                opts.abstract_interpretation = true;
                opts.context_sensitive = true;
                opts.symex = SymexOptions {
                    enabled: true,
                    cross_file: true,
                    interprocedural: true,
                    smt: false,
                };
                opts.backwards_analysis = true;
            }
        }
        opts
    }
}

impl std::fmt::Display for EngineProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineProfile::Fast => write!(f, "fast"),
            EngineProfile::Balanced => write!(f, "balanced"),
            EngineProfile::Deep => write!(f, "deep"),
        }
    }
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Scan project for vulnerabilities
    Scan {
        /// Path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Index mode: auto (default), off (no index), rebuild (force rebuild)
        #[arg(long, value_enum, default_value_t = IndexMode::Auto, help_heading = "Analysis")]
        index: IndexMode,

        /// Output format (defaults to config's default_format, or "console")
        #[arg(short, long, value_enum, help_heading = "Output")]
        format: Option<OutputFormat>,

        /// Severity filter expression: HIGH, HIGH,MEDIUM, or >=MEDIUM
        ///
        /// Filters findings AFTER all severity normalization (e.g. nonprod
        /// downgrades). Only findings matching the expression are emitted.
        /// Case-insensitive. Shell-quote expressions containing ">".
        #[arg(long, help_heading = "Output")]
        severity: Option<String>,

        /// Analysis mode: full (default), ast, cfg, taint
        #[arg(long, value_enum, default_value_t = ScanMode::Full, help_heading = "Analysis")]
        mode: ScanMode,

        /// Named scan profile to apply (e.g. quick, full, ci, taint_only, conservative_large_repo)
        ///
        /// Profiles override scan-related config settings. CLI flags still
        /// take precedence over profile values.
        #[arg(long, help_heading = "Analysis")]
        profile: Option<String>,

        /// Engine-depth shortcut: fast, balanced, or deep.  Sets the full
        /// stack of analysis toggles at once; individual engine flags still
        /// override this after application.
        #[arg(long, value_enum, help_heading = "Analysis")]
        engine_profile: Option<EngineProfile>,

        /// Print the effective engine configuration and exit without
        /// scanning.  Useful for understanding how CLI flags and config
        /// values resolve together.
        #[arg(long, help_heading = "Analysis")]
        explain_engine: bool,

        /// Scan all targets (alias for --mode full)
        #[arg(long, hide = true)]
        all_targets: bool,

        /// Preserve original severity for test/vendor/build paths
        ///
        /// By default, findings in non-production paths are downgraded by one
        /// severity tier. This flag preserves original severity.
        #[arg(long, alias = "include-nonprod", help_heading = "Output")]
        keep_nonprod_severity: bool,

        /// Suppress all human-readable status output
        #[arg(long, help_heading = "Output")]
        quiet: bool,

        /// Print the dynamic-verifier trace to stderr at end-of-verify.
        ///
        /// When dynamic verification is enabled, the verifier records a
        /// per-finding [`crate::dynamic::trace::VerifyTrace`].  Setting this
        /// flag flushes every recorded `TraceEvent` to stderr after each
        /// verdict, matching the stream that already lands in the repro
        /// bundle at `expected/trace.jsonl`.  Off by default so non-interactive
        /// scans stay quiet.
        #[arg(long, help_heading = "Output")]
        verbose: bool,

        /// Exit with code 1 if any finding meets or exceeds this severity
        ///
        /// Useful for CI gating. Example: --fail-on HIGH
        #[arg(long, help_heading = "Output")]
        fail_on: Option<String>,

        /// Disable state-model analysis (resource lifecycle, auth state)
        #[arg(long, help_heading = "Analysis")]
        no_state: bool,

        /// Disable attack-surface ranking (findings are sorted by exploitability by default)
        #[arg(long, help_heading = "Output")]
        no_rank: bool,

        /// Show inline-suppressed findings (dimmed, tagged \[SUPPRESSED\])
        #[arg(long, help_heading = "Output")]
        show_suppressed: bool,

        /// Show all findings: disables category filtering, rollups, and LOW budgets
        #[arg(long = "all", help_heading = "Output")]
        show_all: bool,

        /// Include Quality findings (excluded by default)
        #[arg(long, help_heading = "Output")]
        include_quality: bool,

        /// Maximum total LOW findings to show
        #[arg(long, default_value_t = 20, help_heading = "Output")]
        max_low: u32,

        /// Maximum LOW findings per file
        #[arg(long, default_value_t = 1, help_heading = "Output")]
        max_low_per_file: u32,

        /// Maximum LOW findings per rule
        #[arg(long, default_value_t = 10, help_heading = "Output")]
        max_low_per_rule: u32,

        /// Number of example locations in rollup findings
        #[arg(long, default_value_t = 5, help_heading = "Output")]
        rollup_examples: u32,

        /// Show all instances for a specific rule (bypasses rollup for that rule)
        #[arg(long, help_heading = "Output")]
        show_instances: Option<String>,

        /// Minimum attack-surface score to include in output
        ///
        /// Findings with a rank score below this threshold are suppressed.
        /// Requires ranking to be enabled (has no effect with --no-rank).
        /// Example: --min-score 50
        #[arg(long, help_heading = "Output")]
        min_score: Option<u32>,

        /// Minimum confidence level to include in output
        ///
        /// Values: low, medium, high. Findings below this level are dropped.
        /// JSON/SARIF include all unless filtered.
        #[arg(long, help_heading = "Output")]
        min_confidence: Option<String>,

        /// Drop findings emitted from capped / widened / bailed analysis
        ///
        /// Suppresses any finding whose engine provenance notes indicate
        /// over-reporting (predicate/path widening) or analysis bail
        /// (SSA lowering failure, parse timeout).  Under-report notes
        /// (where the emitted finding is still a real flow but the
        /// result set is a lower bound) are kept.
        ///
        /// Intended for strict CI gates where a finding from non-converged
        /// analysis is worse than no finding.  Applied after ranking and
        /// before the `max_results` truncation.
        #[arg(long, help_heading = "Output")]
        require_converged: bool,

        /// Enable path-constraint solving (default: on)
        #[arg(
            long,
            overrides_with = "no_constraint_solving",
            help_heading = "Engine"
        )]
        constraint_solving: bool,
        /// Disable path-constraint solving
        #[arg(long, overrides_with = "constraint_solving", help_heading = "Engine")]
        no_constraint_solving: bool,

        /// Enable abstract interpretation (default: on)
        #[arg(long, overrides_with = "no_abstract_interp", help_heading = "Engine")]
        abstract_interp: bool,
        /// Disable abstract interpretation
        #[arg(long, overrides_with = "abstract_interp", help_heading = "Engine")]
        no_abstract_interp: bool,

        /// Enable k=1 context-sensitive callee inlining (default: on)
        #[arg(long, overrides_with = "no_context_sensitive", help_heading = "Engine")]
        context_sensitive: bool,
        /// Disable context-sensitive callee inlining
        #[arg(long, overrides_with = "context_sensitive", help_heading = "Engine")]
        no_context_sensitive: bool,

        /// Enable the symex pipeline (default: on)
        #[arg(long, overrides_with = "no_symex", help_heading = "Symex")]
        symex: bool,
        /// Disable the symex pipeline entirely
        #[arg(long, overrides_with = "symex", help_heading = "Symex")]
        no_symex: bool,

        /// Enable cross-file symbolic body execution (default: on)
        #[arg(long, overrides_with = "no_cross_file_symex", help_heading = "Symex")]
        cross_file_symex: bool,
        /// Disable cross-file symbolic body execution
        #[arg(long, overrides_with = "cross_file_symex", help_heading = "Symex")]
        no_cross_file_symex: bool,

        /// Enable interprocedural symex frame stack (default: on)
        #[arg(long, overrides_with = "no_symex_interproc", help_heading = "Symex")]
        symex_interproc: bool,
        /// Disable interprocedural symex
        #[arg(long, overrides_with = "symex_interproc", help_heading = "Symex")]
        no_symex_interproc: bool,

        /// Enable SMT solver backend when nyx is built with the `smt` feature (default: on)
        #[arg(long, overrides_with = "no_smt", help_heading = "Symex")]
        smt: bool,
        /// Disable SMT solver backend
        #[arg(long, overrides_with = "smt", help_heading = "Symex")]
        no_smt: bool,

        /// Enable demand-driven backwards analysis (default: off)
        #[arg(
            long,
            overrides_with = "no_backwards_analysis",
            help_heading = "Engine"
        )]
        backwards_analysis: bool,
        /// Disable demand-driven backwards analysis
        #[arg(long, overrides_with = "backwards_analysis", help_heading = "Engine")]
        no_backwards_analysis: bool,

        /// Override per-file tree-sitter parse timeout (ms). 0 disables the cap.
        #[arg(long, help_heading = "Limits")]
        parse_timeout_ms: Option<u64>,

        /// Maximum taint origins retained per lattice value (default: 32).
        ///
        /// When origin sets exceed this cap, origins are truncated
        /// deterministically (by source location) and an
        /// `OriginsTruncated` engine note is recorded on affected findings.
        /// Raise for very wide codebases where truncation is observed;
        /// lower only when lattice width is a measured bottleneck.
        #[arg(long, help_heading = "Limits")]
        max_origins: Option<u32>,

        /// Maximum abstract heap objects retained per points-to set (default: 32).
        ///
        /// When an intra-procedural points-to set would exceed this cap,
        /// the largest-keyed heap objects are dropped and a
        /// `PointsToTruncated` engine note is recorded on affected findings.
        /// Raise for factory-heavy codebases where truncation is observed;
        /// lower only when points-to width is a measured bottleneck.
        #[arg(long, help_heading = "Limits")]
        max_pointsto: Option<u32>,

        /// Deprecated: use --index off
        #[arg(long, hide = true)]
        no_index: bool,

        /// Deprecated: use --index rebuild
        #[arg(long, hide = true)]
        rebuild_index: bool,

        /// Deprecated: use --severity HIGH
        #[arg(long, hide = true)]
        high_only: bool,

        /// Deprecated: use --mode ast
        #[arg(long, hide = true)]
        ast_only: bool,

        /// Deprecated: use --mode cfg
        #[arg(long, hide = true)]
        cfg_only: bool,

        /// Build a harness and dynamically verify each finding in a sandbox.
        ///
        /// Dynamic verification is on by default. This flag is a no-op when
        /// verification is already enabled via config. Use `--no-verify` to
        /// disable it for a single run. Default builds include dynamic support;
        /// custom `--no-default-features` builds need `--features dynamic`.
        #[cfg_attr(not(feature = "dynamic"), arg(hide = true))]
        #[arg(long, help_heading = "Dynamic", conflicts_with = "no_verify")]
        verify: bool,

        /// Skip dynamic verification for this run.
        ///
        /// Overrides `verify = true` from config. Useful when you want a
        /// fast static-only scan without permanently changing `nyx.toml`.
        #[cfg_attr(not(feature = "dynamic"), arg(hide = true))]
        #[arg(long, help_heading = "Dynamic", conflicts_with = "verify")]
        no_verify: bool,

        /// Also verify `Confidence < Medium` findings dynamically.
        ///
        /// By default only `Confidence >= Medium` findings are verified. Pass
        /// this flag to run verification on all findings regardless of
        /// confidence. Intended for payload tuning and backfill runs.
        #[cfg_attr(not(feature = "dynamic"), arg(hide = true))]
        #[arg(long, help_heading = "Dynamic")]
        verify_all_confidence: bool,

        /// Force the process sandbox backend (less isolation, dev use only).
        ///
        /// By default the docker backend is used when available. This flag
        /// restricts the backend to the in-process runner. Cannot be combined
        /// with `--backend docker`.
        #[cfg_attr(not(feature = "dynamic"), arg(hide = true))]
        #[arg(long, help_heading = "Dynamic")]
        unsafe_sandbox: bool,

        /// Sandbox backend to use for dynamic verification.
        ///
        /// `auto` (default): docker when available, else process.
        /// `docker`: require docker; fail if unavailable.
        /// `process`: in-process runner (same as `--unsafe-sandbox`).
        #[cfg_attr(not(feature = "dynamic"), arg(hide = true))]
        #[arg(long, help_heading = "Dynamic", value_name = "BACKEND")]
        backend: Option<String>,

        /// Process-backend hardening profile applied to every verified finding.
        ///
        /// `standard` (default): baseline only. Linux runs no-new-privs +
        /// memory rlimit; macOS skips the sandbox-exec wrap.
        /// `strict`: full lockdown. Linux layers namespaces, chroot to
        /// workdir, and a default-deny seccomp filter; macOS wraps the
        /// harness with `sandbox-exec -f <cap>.sb`. Opt-in because
        /// interpreted Linux harnesses may SIGSYS until the per-language
        /// seccomp allowlists are expanded.
        #[cfg_attr(not(feature = "dynamic"), arg(hide = true))]
        #[arg(
            long,
            help_heading = "Dynamic",
            value_name = "PROFILE",
            value_parser = ["standard", "strict"],
        )]
        harden: Option<String>,

        /// Read a previous scan's JSON output (or a stripped .nyx/baseline.json)
        /// and diff it against the current scan on stable_hash.
        ///
        /// Emits a verdict diff showing New / Resolved / FlippedConfirmed /
        /// FlippedNotConfirmed transitions. Combine with --gate to enforce CI
        /// policies.
        #[arg(long, value_name = "FILE", help_heading = "Baseline")]
        baseline: Option<String>,

        /// Write a stripped baseline JSON to FILE after scanning.
        ///
        /// The file contains only stable_hash, dynamic_verdict, severity, path,
        /// and rule_id (no source code). A CI job can persist this file to
        /// compare future scans against without leaking source.
        #[arg(long, value_name = "FILE", help_heading = "Baseline")]
        baseline_write: Option<String>,

        /// CI gate to enforce when --baseline is active.
        ///
        /// `no-new-confirmed`: exit 2 if any new Confirmed finding appears.
        /// `resolve-all-confirmed`: exit 2 if any baseline-Confirmed finding
        /// is not fully resolved (absent or NotConfirmed in the current scan).
        #[arg(
            long,
            value_name = "GATE",
            value_parser = ["no-new-confirmed", "resolve-all-confirmed"],
            help_heading = "Baseline"
        )]
        gate: Option<String>,
    },

    /// Submit feedback on a dynamic verification verdict.
    ///
    /// Records a correction or confirmation for a finding's verdict in the
    /// local telemetry log. Requires `--features dynamic`.
    #[cfg_attr(not(feature = "dynamic"), command(hide = true))]
    VerifyFeedback {
        /// Stable finding ID (16-char hex, shown in `nyx scan --verify` output).
        finding_id: String,

        /// Mark this verdict as wrong and record a reason.
        #[arg(long, conflicts_with = "right")]
        wrong: Option<String>,

        /// Confirm this verdict is correct.
        #[arg(long, conflicts_with = "wrong")]
        right: bool,

        /// Upload feedback to Nyx telemetry (not yet implemented; reserved).
        #[arg(long)]
        upload: bool,
    },

    /// Manage project indexes
    Index {
        #[command(subcommand)]
        action: IndexAction,
    },

    /// List all indexed projects
    List {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },

    /// Remove project from index
    Clean {
        /// Project name or path to clean
        project: Option<String>,

        /// Clean all projects
        #[arg(long)]
        all: bool,
    },

    /// Manage analysis configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Browse the built-in rule registry (cap classes + per-language label rules)
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Print the project's attack-surface map.
    ///
    /// Loads the SurfaceMap persisted by the most recent indexed scan
    /// when available, otherwise builds an entry-point-only map by
    /// running the per-language framework probes against the on-disk
    /// source.  Pass `--build` to force a full inline build (pass-1
    /// summary extraction + call-graph construction) when no indexed
    /// scan exists; that populates DataStore / ExternalService /
    /// DangerousLocal nodes the entry-points-only fallback omits.
    /// Use `--format dot` and pipe through `dot -Tsvg` to produce a
    /// renderable graph; `--format svg` does the same in one step when
    /// graphviz is installed locally.
    Surface {
        /// Path to inspect (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Output format: text (default), json, dot, svg
        #[arg(long, value_enum, default_value_t = SurfaceFormat::Text)]
        format: SurfaceFormat,

        /// Build the full SurfaceMap from source even when no indexed
        /// scan exists.  Runs pass-1 summary extraction + call-graph
        /// build inline (same cost as `nyx index build`), then renders
        /// data-store / external-service / dangerous-local nodes plus
        /// reach edges.  Without this flag, an unscanned project
        /// produces an entry-points-only map.
        #[arg(long)]
        build: bool,
    },

    /// Start the local web UI for browsing scan results
    Serve {
        /// Path to scan root (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Port to bind to (overrides config)
        #[arg(short, long)]
        port: Option<u16>,

        /// Host to bind to (overrides config)
        #[arg(long)]
        host: Option<String>,

        /// Don't open browser automatically
        #[arg(long)]
        no_browser: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Print configuration as TOML.  By default shows only the values
    /// that differ from built-in defaults.  Pass `--all` for the full
    /// effective configuration.
    Show {
        /// Print the full effective configuration instead of just
        /// the user's overrides.
        #[arg(long)]
        all: bool,
    },

    /// Print configuration directory path
    Path,

    /// Add a label rule to nyx.local
    AddRule {
        /// Language slug (e.g. javascript, rust, python)
        #[arg(long)]
        lang: String,

        /// Function or property name to match
        #[arg(long)]
        matcher: String,

        /// Rule kind: source, sanitizer, or sink
        #[arg(long)]
        kind: String,

        /// Capability: env_var, html_escape, shell_escape, url_encode, json_parse, file_io, or all
        #[arg(long)]
        cap: String,
    },

    /// Add a terminator function to nyx.local
    AddTerminator {
        /// Language slug (e.g. javascript, rust, python)
        #[arg(long)]
        lang: String,

        /// Function name that terminates execution (e.g. process.exit)
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
pub enum RulesAction {
    /// List built-in rules
    List {
        /// Filter by language slug (e.g. javascript, java, python). Cap-class
        /// entries (`language = "all"`) are always shown unless `--no-class`
        /// is set.
        #[arg(long)]
        lang: Option<String>,

        /// Filter by rule kind (`class`, `source`, `sink`, `sanitizer`).
        #[arg(long)]
        kind: Option<String>,

        /// Show only the cap-class registry entries (one per vulnerability
        /// class), suppressing per-language label rules.
        #[arg(long, conflicts_with = "no_class")]
        class_only: bool,

        /// Suppress cap-class registry entries (show only per-language label
        /// rules and gated sinks).
        #[arg(long)]
        no_class: bool,

        /// Emit JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum IndexAction {
    /// Build or update index for current project
    Build {
        /// Path to index (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Force full rebuild
        #[arg(short, long)]
        force: bool,
    },

    /// Show index status and statistics
    Status {
        /// Project path to check
        #[arg(default_value = ".")]
        path: String,
    },
}
