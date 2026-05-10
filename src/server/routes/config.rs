use crate::commands::config as config_cmd;
use crate::server::app::{AppState, ServerEvent};
use crate::server::models::{LabelEntryView, ProfileView, RuleView, TerminatorView};
use crate::utils::config::{CapName, Config, RuleKind, ScanProfile};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use std::fs;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/config", get(get_config))
        .route("/config/raw", get(get_config_raw).put(put_config_raw))
        .route(
            "/config/rules",
            get(list_rules).post(add_rule).delete(remove_rule),
        )
        .route(
            "/config/terminators",
            get(list_terminators)
                .post(add_terminator)
                .delete(remove_terminator),
        )
        // Sources/sinks/sanitizers split by kind
        .route(
            "/config/sources",
            get(list_sources).post(add_source).delete(remove_source),
        )
        .route(
            "/config/sinks",
            get(list_sinks).post(add_sink).delete(remove_sink),
        )
        .route(
            "/config/sanitizers",
            get(list_sanitizers)
                .post(add_sanitizer)
                .delete(remove_sanitizer),
        )
        // Triage sync toggle
        .route("/config/triage-sync", axum::routing::post(set_triage_sync))
        // Profiles
        .route("/config/profiles", get(list_profiles).post(save_profile))
        .route(
            "/config/profiles/{name}",
            axum::routing::delete(delete_profile),
        )
        .route(
            "/config/profiles/{name}/activate",
            axum::routing::post(activate_profile),
        )
}

async fn get_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config = state.config.read();
    Json(serde_json::to_value(&*config).unwrap_or_default())
}

// ── Raw nyx.local read/write ─────────────────────────────────────────────────

async fn get_config_raw(State(state): State<AppState>) -> Json<serde_json::Value> {
    let local_path = state.config_dir.join("nyx.local");
    let exists = local_path.exists();
    let content = if exists {
        fs::read_to_string(&local_path).unwrap_or_default()
    } else {
        String::new()
    };

    Json(serde_json::json!({
        "path": local_path.display().to_string(),
        "exists": exists,
        "content": content,
    }))
}

async fn put_config_raw(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let content = body
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("missing content field"))?
        .to_string();

    // Validate by parsing into Config (round-trip check).
    let parsed: Config =
        toml::from_str(&content).map_err(|e| bad_request(&format!("invalid TOML: {e}")))?;
    if let Err(errs) = parsed.validate() {
        let joined = errs
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(bad_request(&format!("config validation failed: {joined}")));
    }

    let local_path = state.config_dir.join("nyx.local");
    fs::write(&local_path, &content)
        .map_err(|e| bad_request(&format!("failed to write {}: {e}", local_path.display())))?;

    // Reload the merged config so live state matches the file.
    match Config::load(&state.config_dir) {
        Ok((reloaded, _note)) => {
            *state.config.write() = reloaded;
        }
        Err(e) => return Err(bad_request(&format!("config reload failed: {e}"))),
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);

    Ok(Json(serde_json::json!({
        "status": "ok",
        "path": local_path.display().to_string(),
        "bytes": content.len(),
    })))
}

// ── Custom rules (existing endpoints) ────────────────────────────────────────

async fn list_rules(State(state): State<AppState>) -> Json<Vec<RuleView>> {
    let config = state.config.read();
    let mut rules = Vec::new();
    for (lang, lang_cfg) in &config.analysis.languages {
        for rule in &lang_cfg.rules {
            rules.push(RuleView {
                lang: lang.clone(),
                matchers: rule.matchers.clone(),
                kind: rule.kind.to_string(),
                cap: format!("{:?}", rule.cap).to_ascii_lowercase(),
            });
        }
    }
    Json(rules)
}

async fn add_rule(
    State(state): State<AppState>,
    Json(rule): Json<RuleView>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let rule_kind: RuleKind = rule.kind.parse().map_err(|e: String| bad_request(&e))?;
    let cap_name: CapName = rule.cap.parse().map_err(|e: String| bad_request(&e))?;

    if let Err(e) = config_cmd::add_rule(
        &state.config_dir,
        &rule.lang,
        &rule.matchers.join(","),
        &rule.kind,
        &rule.cap,
    ) {
        return Err(bad_request(&e.to_string()));
    }

    {
        let mut config = state.config.write();
        let lang_cfg = config
            .analysis
            .languages
            .entry(rule.lang.clone())
            .or_default();

        let new_rule = crate::utils::config::ConfigLabelRule {
            matchers: rule.matchers,
            kind: rule_kind,
            cap: cap_name,
            case_sensitive: false,
        };

        if !lang_cfg.rules.contains(&new_rule) {
            lang_cfg.rules.push(new_rule);
        }
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    ))
}

async fn remove_rule(
    State(state): State<AppState>,
    Json(rule): Json<RuleView>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let rule_kind: RuleKind = rule.kind.parse().map_err(|e: String| bad_request(&e))?;
    let cap_name: CapName = rule.cap.parse().map_err(|e: String| bad_request(&e))?;

    let removed = {
        let mut config = state.config.write();
        if let Some(lang_cfg) = config.analysis.languages.get_mut(&rule.lang) {
            let before = lang_cfg.rules.len();
            lang_cfg.rules.retain(|r| {
                !(r.matchers == rule.matchers && r.kind == rule_kind && r.cap == cap_name)
            });
            lang_cfg.rules.len() < before
        } else {
            false
        }
    };

    if removed {
        let config = state.config.read();
        let local_path = state.config_dir.join("nyx.local");
        let _ = config_cmd::save_local_config(&local_path, &config);
        let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    }

    Ok(Json(serde_json::json!({ "removed": removed })))
}

// ── Terminators ──────────────────────────────────────────────────────────────

async fn list_terminators(State(state): State<AppState>) -> Json<Vec<TerminatorView>> {
    let config = state.config.read();
    let mut terminators = Vec::new();
    for (lang, lang_cfg) in &config.analysis.languages {
        for name in &lang_cfg.terminators {
            terminators.push(TerminatorView {
                lang: lang.clone(),
                name: name.clone(),
            });
        }
    }
    Json(terminators)
}

async fn add_terminator(
    State(state): State<AppState>,
    Json(term): Json<TerminatorView>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = config_cmd::add_terminator(&state.config_dir, &term.lang, &term.name) {
        return Err(bad_request(&e.to_string()));
    }

    {
        let mut config = state.config.write();
        let lang_cfg = config
            .analysis
            .languages
            .entry(term.lang.clone())
            .or_default();
        if !lang_cfg.terminators.contains(&term.name) {
            lang_cfg.terminators.push(term.name);
        }
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    ))
}

async fn remove_terminator(
    State(state): State<AppState>,
    Json(term): Json<TerminatorView>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let removed = {
        let mut config = state.config.write();
        if let Some(lang_cfg) = config.analysis.languages.get_mut(&term.lang) {
            let before = lang_cfg.terminators.len();
            lang_cfg.terminators.retain(|n| n != &term.name);
            lang_cfg.terminators.len() < before
        } else {
            false
        }
    };

    if removed {
        let config = state.config.read();
        let local_path = state.config_dir.join("nyx.local");
        let _ = config_cmd::save_local_config(&local_path, &config);
        let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    }

    Ok(Json(serde_json::json!({ "removed": removed })))
}

// ── Sources / Sinks / Sanitizers (by kind) ───────────────────────────────────

fn list_by_kind(state: &AppState, target_kind: &str) -> Vec<LabelEntryView> {
    // Built-in rules live on /api/rules, keep this endpoint focused on the
    // user's own additions in nyx.local.
    let target_rule_kind = match target_kind {
        "source" => RuleKind::Source,
        "sanitizer" => RuleKind::Sanitizer,
        "sink" => RuleKind::Sink,
        _ => return Vec::new(),
    };

    let config = state.config.read();
    let mut out: Vec<LabelEntryView> = Vec::new();
    for (lang, lang_cfg) in &config.analysis.languages {
        for cr in &lang_cfg.rules {
            if cr.kind == target_rule_kind {
                out.push(LabelEntryView {
                    lang: lang.clone(),
                    matchers: cr.matchers.clone(),
                    cap: cr.cap.to_string(),
                    case_sensitive: cr.case_sensitive,
                    is_builtin: false,
                });
            }
        }
    }
    out
}

fn add_by_kind(
    state: &AppState,
    entry: LabelEntryView,
    target_kind: RuleKind,
) -> Result<(), String> {
    let cap_name: CapName = entry.cap.parse().map_err(|e: String| e)?;

    if let Err(e) = config_cmd::add_rule(
        &state.config_dir,
        &entry.lang,
        &entry.matchers.join(","),
        &target_kind.to_string(),
        &entry.cap,
    ) {
        return Err(e.to_string());
    }

    {
        let mut config = state.config.write();
        let lang_cfg = config
            .analysis
            .languages
            .entry(entry.lang.clone())
            .or_default();

        let new_rule = crate::utils::config::ConfigLabelRule {
            matchers: entry.matchers,
            kind: target_kind,
            cap: cap_name,
            case_sensitive: entry.case_sensitive,
        };

        if !lang_cfg.rules.contains(&new_rule) {
            lang_cfg.rules.push(new_rule);
        }
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    Ok(())
}

fn remove_by_kind(state: &AppState, entry: LabelEntryView, target_kind: RuleKind) -> bool {
    if entry.is_builtin {
        return false; // cannot remove built-in rules
    }

    let cap_name: CapName = match entry.cap.parse() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let removed = {
        let mut config = state.config.write();
        if let Some(lang_cfg) = config.analysis.languages.get_mut(&entry.lang) {
            let before = lang_cfg.rules.len();
            lang_cfg.rules.retain(|r| {
                !(r.matchers == entry.matchers && r.kind == target_kind && r.cap == cap_name)
            });
            lang_cfg.rules.len() < before
        } else {
            false
        }
    };

    if removed {
        let config = state.config.read();
        let local_path = state.config_dir.join("nyx.local");
        let _ = config_cmd::save_local_config(&local_path, &config);
        let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    }

    removed
}

async fn list_sources(State(state): State<AppState>) -> Json<Vec<LabelEntryView>> {
    Json(list_by_kind(&state, "source"))
}

async fn add_source(
    State(state): State<AppState>,
    Json(entry): Json<LabelEntryView>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    add_by_kind(&state, entry, RuleKind::Source).map_err(|e| bad_request(&e))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    ))
}

async fn remove_source(
    State(state): State<AppState>,
    Json(entry): Json<LabelEntryView>,
) -> Json<serde_json::Value> {
    let removed = remove_by_kind(&state, entry, RuleKind::Source);
    Json(serde_json::json!({ "removed": removed }))
}

async fn list_sinks(State(state): State<AppState>) -> Json<Vec<LabelEntryView>> {
    Json(list_by_kind(&state, "sink"))
}

async fn add_sink(
    State(state): State<AppState>,
    Json(entry): Json<LabelEntryView>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    add_by_kind(&state, entry, RuleKind::Sink).map_err(|e| bad_request(&e))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    ))
}

async fn remove_sink(
    State(state): State<AppState>,
    Json(entry): Json<LabelEntryView>,
) -> Json<serde_json::Value> {
    let removed = remove_by_kind(&state, entry, RuleKind::Sink);
    Json(serde_json::json!({ "removed": removed }))
}

async fn list_sanitizers(State(state): State<AppState>) -> Json<Vec<LabelEntryView>> {
    Json(list_by_kind(&state, "sanitizer"))
}

async fn add_sanitizer(
    State(state): State<AppState>,
    Json(entry): Json<LabelEntryView>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    add_by_kind(&state, entry, RuleKind::Sanitizer).map_err(|e| bad_request(&e))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    ))
}

async fn remove_sanitizer(
    State(state): State<AppState>,
    Json(entry): Json<LabelEntryView>,
) -> Json<serde_json::Value> {
    let removed = remove_by_kind(&state, entry, RuleKind::Sanitizer);
    Json(serde_json::json!({ "removed": removed }))
}

// ── Profiles ─────────────────────────────────────────────────────────────────

const BUILTIN_PROFILE_NAMES: &[&str] = &[
    "quick",
    "full",
    "ci",
    "taint_only",
    "conservative_large_repo",
];

async fn list_profiles(State(state): State<AppState>) -> Json<Vec<ProfileView>> {
    let config = state.config.read();
    let mut profiles: Vec<ProfileView> = Vec::new();

    // Built-in profiles
    for &name in BUILTIN_PROFILE_NAMES {
        if let Some(p) = config.resolve_profile(name) {
            let is_user_override = config.profiles.contains_key(name);
            profiles.push(ProfileView {
                name: name.to_string(),
                is_builtin: !is_user_override,
                settings: serde_json::to_value(&p).unwrap_or_default(),
            });
        }
    }

    // User profiles not matching a built-in name
    for (name, p) in &config.profiles {
        if !BUILTIN_PROFILE_NAMES.contains(&name.as_str()) {
            profiles.push(ProfileView {
                name: name.clone(),
                is_builtin: false,
                settings: serde_json::to_value(p).unwrap_or_default(),
            });
        }
    }

    Json(profiles)
}

async fn save_profile(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let name = body["name"]
        .as_str()
        .ok_or_else(|| bad_request("missing name"))?
        .to_string();
    let settings: ScanProfile =
        serde_json::from_value(body.get("settings").cloned().unwrap_or_default())
            .map_err(|e| bad_request(&e.to_string()))?;

    {
        let mut config = state.config.write();
        config.profiles.insert(name.clone(), settings);
        let local_path = state.config_dir.join("nyx.local");
        config_cmd::save_local_config(&local_path, &config)
            .map_err(|e| bad_request(&e.to_string()))?;
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok", "name": name })),
    ))
}

async fn delete_profile(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if BUILTIN_PROFILE_NAMES.contains(&name.as_str()) {
        let config = state.config.read();
        if !config.profiles.contains_key(&name) {
            return Err(bad_request("cannot delete built-in profile"));
        }
    }

    let removed = {
        let mut config = state.config.write();
        let existed = config.profiles.remove(&name).is_some();
        if existed {
            let local_path = state.config_dir.join("nyx.local");
            let _ = config_cmd::save_local_config(&local_path, &config);
        }
        existed
    };

    if removed {
        let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    }

    Ok(Json(serde_json::json!({ "removed": removed })))
}

async fn activate_profile(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    {
        let mut config = state.config.write();
        config
            .apply_profile(&name)
            .map_err(|e| bad_request(&e.to_string()))?;
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    Ok(Json(serde_json::json!({ "status": "ok", "profile": name })))
}

// ── Triage Sync ──────────────────────────────────────────────────────────────

async fn set_triage_sync(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let enabled = body["enabled"]
        .as_bool()
        .ok_or_else(|| bad_request("missing enabled field"))?;

    {
        let mut config = state.config.write();
        config.server.triage_sync = enabled;
        // Note: triage_sync is in the server section, which save_local_config
        // doesn't currently persist. We write the full config here.
        let local_path = state.config_dir.join("nyx.local");
        config_cmd::save_local_config(&local_path, &config)
            .map_err(|e| bad_request(&e.to_string()))?;
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    Ok(Json(
        serde_json::json!({ "status": "ok", "triage_sync": enabled }),
    ))
}

fn bad_request(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
}
