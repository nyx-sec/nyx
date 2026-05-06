use crate::commands::config as config_cmd;
use crate::labels::{self, RuleInfo};
use crate::server::app::{AppState, ServerEvent};
use crate::server::models::{RelatedFindingView, RuleDetailView, RuleListItem};
use crate::utils::config::RuleKind;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/rules", get(list_rules))
        .route("/rules/{id}", get(get_rule))
        .route("/rules/{id}/toggle", post(toggle_rule))
        .route("/rules/clone", post(clone_rule))
}

/// Build the full list of rules: built-in + custom, with disabled state applied.
fn build_rule_list(state: &AppState) -> Vec<RuleInfo> {
    let config = state.config.read();
    let mut rules = labels::enumerate_builtin_rules();

    // Mark disabled rules
    for rule in &mut rules {
        if config.analysis.disabled_rules.contains(&rule.id) {
            rule.enabled = false;
        }
    }

    // Add custom rules from config
    for (lang, lang_cfg) in &config.analysis.languages {
        let canonical = labels::canonical_lang(lang);
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
                enabled,
            });
        }
    }

    rules
}

/// GET /api/rules, list all rules with finding counts.
async fn list_rules(State(state): State<AppState>) -> Json<Vec<RuleListItem>> {
    let rules = build_rule_list(&state);

    // Best-effort finding count: read latest findings from job manager
    let findings = state.job_manager.latest_findings();
    let finding_counts = compute_finding_counts(&rules, &findings);

    let items: Vec<RuleListItem> = rules
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let (count, suppressed) = finding_counts.get(i).copied().unwrap_or((0, 0));
            let rate = if count > 0 {
                suppressed as f64 / count as f64
            } else {
                0.0
            };
            RuleListItem {
                id: r.id,
                title: r.title,
                language: r.language,
                kind: r.kind,
                cap: r.cap,
                matchers: r.matchers,
                enabled: r.enabled,
                is_custom: r.is_custom,
                is_gated: r.is_gated,
                is_class: r.is_class,
                case_sensitive: r.case_sensitive,
                finding_count: count,
                suppression_rate: rate,
            }
        })
        .collect();

    Json(items)
}

/// GET /api/rules/:id, full detail for one rule.
async fn get_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RuleDetailView>, StatusCode> {
    let rules = build_rule_list(&state);
    let rule = rules
        .iter()
        .find(|r| r.id == id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let findings = state.job_manager.latest_findings();
    let examples = match_findings_for_rule(rule, &findings, 5);
    let total = match_findings_for_rule(rule, &findings, usize::MAX).len();
    let suppressed = examples
        .iter()
        .filter(|f| f.severity == crate::patterns::Severity::Low)
        .count();
    let rate = if total > 0 {
        suppressed as f64 / total as f64
    } else {
        0.0
    };

    Ok(Json(RuleDetailView {
        id: rule.id.clone(),
        title: rule.title.clone(),
        language: rule.language.clone(),
        kind: rule.kind.clone(),
        cap: rule.cap.clone(),
        matchers: rule.matchers.clone(),
        case_sensitive: rule.case_sensitive,
        enabled: rule.enabled,
        is_custom: rule.is_custom,
        is_gated: rule.is_gated,
        is_class: rule.is_class,
        finding_count: total,
        suppression_rate: rate,
        example_findings: examples,
    }))
}

/// POST /api/rules/:id/toggle, enable/disable a rule.
async fn toggle_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    {
        let mut config = state.config.write();
        if let Some(pos) = config.analysis.disabled_rules.iter().position(|r| r == &id) {
            config.analysis.disabled_rules.remove(pos);
        } else {
            config.analysis.disabled_rules.push(id.clone());
        }

        let local_path = state.config_dir.join("nyx.local");
        config_cmd::save_local_config(&local_path, &config)
            .map_err(|e| bad_request(&e.to_string()))?;
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    Ok(Json(serde_json::json!({ "status": "ok", "rule_id": id })))
}

/// POST /api/rules/clone, clone a built-in rule to custom.
async fn clone_rule(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let rule_id_str = body["rule_id"]
        .as_str()
        .ok_or_else(|| bad_request("missing rule_id"))?;

    // Find the built-in rule
    let builtins = labels::enumerate_builtin_rules();
    let source = builtins
        .iter()
        .find(|r| r.id == rule_id_str)
        .ok_or_else(|| bad_request("rule not found or not built-in"))?;

    // Convert to ConfigLabelRule and add to config
    let kind: RuleKind = match source.kind.as_str() {
        "source" => RuleKind::Source,
        "sanitizer" => RuleKind::Sanitizer,
        "sink" => RuleKind::Sink,
        _ => return Err(bad_request("invalid kind")),
    };

    let cap_name: crate::utils::config::CapName =
        source.cap.parse().map_err(|e: String| bad_request(&e))?;

    let new_rule = crate::utils::config::ConfigLabelRule {
        matchers: source.matchers.clone(),
        kind,
        cap: cap_name,
        case_sensitive: source.case_sensitive,
    };

    let new_id;
    {
        let mut config = state.config.write();
        let lang_cfg = config
            .analysis
            .languages
            .entry(source.language.clone())
            .or_default();

        if !lang_cfg.rules.contains(&new_rule) {
            lang_cfg.rules.push(new_rule);
        }

        new_id = labels::custom_rule_id(&source.language, &source.kind, &source.matchers);

        let local_path = state.config_dir.join("nyx.local");
        config_cmd::save_local_config(&local_path, &config)
            .map_err(|e| bad_request(&e.to_string()))?;
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok", "new_id": new_id })),
    ))
}

/// Compute (finding_count, suppressed_count) for each rule by matching
/// finding evidence against rule matchers.
fn compute_finding_counts(
    rules: &[RuleInfo],
    findings: &[crate::commands::scan::Diag],
) -> Vec<(usize, usize)> {
    let mut counts: Vec<(usize, usize)> = vec![(0, 0); rules.len()];

    for d in findings {
        // Try to match each finding against rules by checking if the finding's
        // evidence sink/source snippet contains any of the rule's matchers
        let sink_snippet = d
            .evidence
            .as_ref()
            .and_then(|e| e.sink.as_ref())
            .and_then(|s| s.snippet.as_deref())
            .unwrap_or("");
        let source_snippet = d
            .evidence
            .as_ref()
            .and_then(|e| e.source.as_ref())
            .and_then(|s| s.snippet.as_deref())
            .unwrap_or("");

        for (i, rule) in rules.iter().enumerate() {
            let matched = rule
                .matchers
                .iter()
                .any(|m| sink_snippet.contains(m.as_str()) || source_snippet.contains(m.as_str()));
            if matched {
                counts[i].0 += 1;
                if d.suppressed {
                    counts[i].1 += 1;
                }
            }
        }
    }

    counts
}

/// Find findings matching a rule's matchers, returning up to `limit` examples.
fn match_findings_for_rule(
    rule: &RuleInfo,
    findings: &[crate::commands::scan::Diag],
    limit: usize,
) -> Vec<RelatedFindingView> {
    let mut out = Vec::new();

    for (i, d) in findings.iter().enumerate() {
        if out.len() >= limit {
            break;
        }
        let sink_snippet = d
            .evidence
            .as_ref()
            .and_then(|e| e.sink.as_ref())
            .and_then(|s| s.snippet.as_deref())
            .unwrap_or("");
        let source_snippet = d
            .evidence
            .as_ref()
            .and_then(|e| e.source.as_ref())
            .and_then(|s| s.snippet.as_deref())
            .unwrap_or("");

        let matched = rule
            .matchers
            .iter()
            .any(|m| sink_snippet.contains(m.as_str()) || source_snippet.contains(m.as_str()));
        if matched {
            out.push(RelatedFindingView {
                index: i,
                rule_id: d.id.clone(),
                path: d.path.clone(),
                line: d.line,
                severity: d.severity,
            });
        }
    }

    out
}

fn bad_request(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
}
