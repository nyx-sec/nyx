//! `nyx rules` subcommand.
//!
//! Surfaces the rule registry from the terminal so users can enumerate
//! the same content that the dashboard's `/api/rules` endpoint and the
//! browser's Rules page show.  The output composes built-in cap-class
//! entries (one per `Cap` with a canonical rule id), per-language label
//! rules (sink/source/sanitizer), gated sinks, and any custom rules
//! defined in the user's config.

use crate::cli::RulesAction;
use crate::errors::NyxResult;
use crate::labels::{self, RuleInfo};
use crate::utils::config::{Config, RuleKind};
use console::style;

pub fn handle(action: RulesAction, config: &Config) -> NyxResult<()> {
    match action {
        RulesAction::List {
            lang,
            kind,
            class_only,
            no_class,
            json: as_json,
        } => list(
            config,
            lang.as_deref(),
            kind.as_deref(),
            class_only,
            no_class,
            as_json,
        ),
    }
}

fn list(
    config: &Config,
    lang_filter: Option<&str>,
    kind_filter: Option<&str>,
    class_only: bool,
    no_class: bool,
    as_json: bool,
) -> NyxResult<()> {
    let mut rules = labels::enumerate_builtin_rules();

    // Apply disabled-rules overlay so the CLI matches the dashboard view.
    for rule in &mut rules {
        if config.analysis.disabled_rules.contains(&rule.id) {
            rule.enabled = false;
        }
    }

    // Append custom rules from config.  Mirrors the projection in
    // `src/server/routes/rules.rs::build_rule_list`.
    for (cfg_lang, lang_cfg) in &config.analysis.languages {
        let canonical = labels::canonical_lang(cfg_lang);
        for cr in &lang_cfg.rules {
            let kind_str = match cr.kind {
                RuleKind::Source => "source",
                RuleKind::Sanitizer => "sanitizer",
                RuleKind::Sink => "sink",
            };
            let id = labels::custom_rule_id(canonical, kind_str, &cr.matchers);
            let first = cr.matchers.first().map(|s| s.as_str()).unwrap_or("?");
            let title = format!("{} (custom {})", first, kind_str);
            let cap = cr.cap.to_cap();
            let enabled = !config.analysis.disabled_rules.contains(&id);
            rules.push(RuleInfo {
                id,
                title,
                language: canonical.to_string(),
                kind: kind_str.to_string(),
                cap: labels::cap_to_name(cap).to_string(),
                cap_bits: cap.bits(),
                matchers: cr.matchers.clone(),
                case_sensitive: cr.case_sensitive,
                is_custom: true,
                is_gated: false,
                is_class: false,
                emission_active: true,
                enabled,
            });
        }
    }

    // Filter.
    let lang_filter_canonical = lang_filter.map(labels::canonical_lang);
    rules.retain(|r| {
        if class_only && !r.is_class {
            return false;
        }
        if no_class && r.is_class {
            return false;
        }
        if let Some(want) = lang_filter_canonical {
            // Cap-class entries (`language == "all"`) are language-agnostic;
            // surface them alongside any language filter unless explicitly
            // suppressed via `--no-class`.
            if r.language != want && r.language != "all" {
                return false;
            }
        }
        if let Some(want) = kind_filter
            && !r.kind.eq_ignore_ascii_case(want)
        {
            return false;
        }
        true
    });

    if as_json {
        let body = serde_json::to_string_pretty(&rules)
            .map_err(|e| crate::errors::NyxError::Msg(format!("rules JSON serialise: {e}")))?;
        println!("{body}");
        return Ok(());
    }

    if rules.is_empty() {
        println!("{}", style("(no rules match the supplied filters)").dim());
        return Ok(());
    }

    // Header.
    println!(
        "{}",
        style("Rules (built-in registry, per-language labels, and custom rules from config)")
            .bold()
    );
    println!();

    // Cap-class section first, distinct from per-language entries.
    let class_rules: Vec<&RuleInfo> = rules.iter().filter(|r| r.is_class).collect();
    if !class_rules.is_empty() {
        println!("  {}", style("Vulnerability classes").cyan().bold());
        for r in &class_rules {
            print_class_row(r);
        }
        println!();
    }

    let builtin_label_rules: Vec<&RuleInfo> = rules
        .iter()
        .filter(|r| !r.is_class && !r.is_custom)
        .collect();
    if !builtin_label_rules.is_empty() {
        println!("  {}", style("Built-in label rules").cyan().bold());
        for r in &builtin_label_rules {
            print_label_row(r);
        }
        println!();
    }

    let custom_rules: Vec<&RuleInfo> = rules.iter().filter(|r| r.is_custom).collect();
    if !custom_rules.is_empty() {
        println!("  {}", style("Custom rules (from config)").cyan().bold());
        for r in &custom_rules {
            print_label_row(r);
        }
        println!();
    }

    println!(
        "{}",
        style(format!(
            "{} class · {} built-in label · {} custom · {} total",
            class_rules.len(),
            builtin_label_rules.len(),
            custom_rules.len(),
            rules.len()
        ))
        .dim()
    );

    Ok(())
}

fn print_class_row(r: &RuleInfo) {
    let status = if r.enabled {
        style("on ").green().to_string()
    } else {
        style("off").red().dim().to_string()
    };
    // Forward-declared classes (registered but not yet wired through
    // `ast.rs::diag_for_finding`) carry a tag so users don't expect
    // findings under the class id; live findings still surface under
    // the legacy `taint-unsanitised-flow` rule id.
    let tag = if r.emission_active {
        String::new()
    } else {
        format!(" {}", style("(forward-declared)").yellow())
    };
    println!(
        "    {} {:<32} {} {}{}",
        status,
        style(&r.id).white().bold(),
        style(format!("[{}]", r.cap)).dim(),
        style(&r.title).dim(),
        tag,
    );
}

fn print_label_row(r: &RuleInfo) {
    let status = if r.enabled {
        style("on ").green().to_string()
    } else {
        style("off").red().dim().to_string()
    };
    let tag = if r.is_custom {
        style(" custom").yellow().to_string()
    } else if r.is_gated {
        style(" gated").magenta().to_string()
    } else {
        String::new()
    };
    let matchers = if r.matchers.is_empty() {
        String::new()
    } else {
        let joined = r.matchers.join(", ");
        format!("  {joined}")
    };
    println!(
        "    {} {:<10} {:<10} {:<14}{}{}",
        status,
        style(&r.language).cyan(),
        style(&r.kind).white(),
        style(&r.cap).dim(),
        tag,
        style(matchers).dim(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::Config;

    #[test]
    fn list_runs_without_panic_default_config() {
        let cfg = Config::default();
        // Plain list, no filters.
        list(&cfg, None, None, false, false, false).unwrap();
        // Class-only.
        list(&cfg, None, None, true, false, false).unwrap();
        // JSON output.
        list(&cfg, None, None, false, false, true).unwrap();
        // Lang + kind filters.
        list(&cfg, Some("javascript"), Some("sink"), false, true, false).unwrap();
    }
}
