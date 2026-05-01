//! Static rule-id → OWASP Top-10 (2021) mapping for the dashboard.
//!
//! Rule IDs follow the convention `{lang}.{family}.{name}` (e.g. `js.xss.outer_html`).
//! The family segment is what determines the bucket. Conservative, when in doubt,
//! map to the closest fit; rules with no obvious bucket are left unbucketed.

use crate::server::models::OwaspBucket;
use std::collections::HashMap;

/// Extract the family token from a rule ID. Handles two ID shapes:
///   1. `lang.family.name`, typical (e.g. `js.xss.outer_html`)
///   2. `family-subname` or single-segment, engine-emitted (e.g.
///      `state-resource-leak`, `taint-unsanitised-flow`, `cfg-error-fallthrough`)
fn extract_family(rule_id: &str) -> &str {
    if let Some(idx) = rule_id.find('.') {
        let after = &rule_id[idx + 1..];
        return match after.find('.') {
            Some(n) => &after[..n],
            None => after,
        };
    }
    if let Some(idx) = rule_id.find('-') {
        return &rule_id[..idx];
    }
    rule_id
}

/// Return the OWASP 2021 (code, label) pair for a given rule id, or `None` if unmapped.
pub fn owasp_bucket_for(rule_id: &str) -> Option<(&'static str, &'static str)> {
    let family = extract_family(rule_id);
    if family.is_empty() {
        return None;
    }

    Some(match family {
        // A01, Broken Access Control
        "auth" | "csrf" | "mass_assign" | "path" | "redirect" => ("A01", "Broken Access Control"),
        // A02, Cryptographic Failures
        "crypto" | "secrets" => ("A02", "Cryptographic Failures"),
        // A03, Injection (covers SQLi, XSS, command, code-eval, template, NoSQL, LDAP, reflection,
        // and engine-level taint findings without a more specific family tag).
        "sqli" | "xss" | "cmdi" | "code_exec" | "template" | "nosql" | "ldap" | "reflection"
        | "taint" => ("A03", "Injection"),
        // A05, Security Misconfiguration (TLS verify off, cookie flags, prototype pollution)
        "config" | "transport" | "prototype" => ("A05", "Security Misconfiguration"),
        // A08, Software and Data Integrity Failures
        "deser" => ("A08", "Software and Data Integrity Failures"),
        // A09, Logging & Monitoring Failures
        "log" => ("A09", "Logging and Monitoring Failures"),
        // A10, SSRF
        "ssrf" => ("A10", "Server-Side Request Forgery"),
        // Memory-safety + state-machine resource lifecycle bugs, closest OWASP fit is
        // A04 Insecure Design (defensive depth).
        "memory" | "state" => ("A04", "Insecure Design"),
        // Quality findings (e.g. rs.quality.unwrap) and CFG structural issues
        // (cfg-error-fallthrough) are reliability / code-health, not direct OWASP
        // categories. We return None so they don't pollute the security buckets.
        _ => return None,
    })
}

/// Bucket all rule-id counts into OWASP categories, returning sorted-desc.
pub fn bucket_findings(by_rule: &HashMap<String, usize>) -> Vec<OwaspBucket> {
    let mut totals: HashMap<&'static str, (&'static str, usize)> = HashMap::new();
    for (rule_id, &count) in by_rule {
        if let Some((code, label)) = owasp_bucket_for(rule_id) {
            let entry = totals.entry(code).or_insert((label, 0));
            entry.1 += count;
        }
    }
    let mut out: Vec<OwaspBucket> = totals
        .into_iter()
        .map(|(code, (label, count))| OwaspBucket {
            code: code.to_string(),
            label: label.to_string(),
            count,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.code.cmp(&b.code)));
    out
}

/// Bucket rule-id counts into issue categories using the family segment.
/// Broader than OWASP, with friendlier labels (e.g. "Tainted Flow", "Code Quality").
pub fn issue_categories(
    by_rule: &HashMap<String, usize>,
) -> Vec<crate::server::models::IssueCategoryBucket> {
    let mut totals: HashMap<&'static str, usize> = HashMap::new();
    for (rule_id, &count) in by_rule {
        let label = issue_category_label(rule_id);
        *totals.entry(label).or_insert(0) += count;
    }
    let mut out: Vec<_> = totals
        .into_iter()
        .map(
            |(label, count)| crate::server::models::IssueCategoryBucket {
                label: label.to_string(),
                count,
            },
        )
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.label.cmp(&b.label)));
    out
}

fn issue_category_label(rule_id: &str) -> &'static str {
    // `taint-data-exfiltration` and the legacy `taint-unsanitised-flow`
    // share the `taint` family token, but the exfil class targets a
    // different threat (sensitive data leaving the trust boundary, not
    // attacker payload entering it).  Surface it as its own bucket so the
    // dashboard category badge matches the rule semantics.
    if rule_id.starts_with("taint-data-exfiltration") {
        return "Data Exfiltration";
    }
    match extract_family(rule_id) {
        "sqli" => "SQL Injection",
        "xss" => "Cross-Site Scripting",
        "cmdi" => "Command Injection",
        "code_exec" => "Code Execution",
        "deser" => "Deserialization",
        "ssrf" => "SSRF",
        "path" => "Path Traversal",
        "auth" => "Access Control",
        "csrf" => "CSRF",
        "mass_assign" => "Mass Assignment",
        "crypto" => "Weak Crypto",
        "secrets" => "Hardcoded Secrets",
        "config" => "Misconfiguration",
        "transport" => "Insecure Transport",
        "prototype" => "Prototype Pollution",
        "memory" => "Memory Safety",
        "reflection" => "Reflection",
        "redirect" => "Open Redirect",
        "log" => "Logging",
        "template" => "Template Injection",
        "taint" => "Tainted Flow",
        "state" => "Resource Lifecycle",
        "cfg" => "Control-Flow",
        "quality" => "Code Quality",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_xss_to_a03() {
        assert_eq!(
            owasp_bucket_for("js.xss.outer_html"),
            Some(("A03", "Injection"))
        );
    }

    #[test]
    fn maps_auth_to_a01() {
        assert_eq!(
            owasp_bucket_for("rs.auth.missing_ownership_check"),
            Some(("A01", "Broken Access Control"))
        );
    }

    #[test]
    fn unknown_family_returns_none() {
        assert_eq!(owasp_bucket_for("js.weirdthing.foo"), None);
    }

    #[test]
    fn malformed_rule_returns_none() {
        // single-segment "not" → family "not" → unmapped → None
        assert_eq!(owasp_bucket_for("not-a-rule"), None);
        // "js.onlytwo", family is "onlytwo" which is unmapped
        assert_eq!(owasp_bucket_for("js.onlytwo"), None);
    }

    #[test]
    fn extract_family_handles_dashed_ids() {
        assert_eq!(extract_family("state-resource-leak"), "state");
        assert_eq!(extract_family("taint-unsanitised-flow"), "taint");
        assert_eq!(extract_family("cfg-error-fallthrough"), "cfg");
        assert_eq!(extract_family("rs.quality.unwrap"), "quality");
        assert_eq!(extract_family(""), "");
    }

    #[test]
    fn taint_findings_bucket_to_a03() {
        assert_eq!(
            owasp_bucket_for("taint-unsanitised-flow"),
            Some(("A03", "Injection"))
        );
    }

    #[test]
    fn quality_and_cfg_are_not_owasp() {
        assert_eq!(owasp_bucket_for("rs.quality.unwrap"), None);
        assert_eq!(owasp_bucket_for("cfg-error-fallthrough"), None);
    }

    #[test]
    fn issue_category_handles_engine_ids() {
        assert_eq!(issue_category_label("rs.quality.unwrap"), "Code Quality");
        assert_eq!(
            issue_category_label("state-resource-leak"),
            "Resource Lifecycle"
        );
        assert_eq!(
            issue_category_label("cfg-error-fallthrough"),
            "Control-Flow"
        );
        assert_eq!(
            issue_category_label("taint-unsanitised-flow"),
            "Tainted Flow"
        );
    }

    #[test]
    fn bucket_findings_sorts_desc() {
        let mut m = HashMap::new();
        m.insert("js.xss.outer_html".to_string(), 3);
        m.insert("rs.auth.missing_ownership_check".to_string(), 5);
        m.insert("js.crypto.math_random".to_string(), 2);
        let out = bucket_findings(&m);
        assert_eq!(out[0].code, "A01");
        assert_eq!(out[0].count, 5);
        assert_eq!(out[1].code, "A03");
        assert_eq!(out[1].count, 3);
        assert_eq!(out[2].code, "A02");
        assert_eq!(out[2].count, 2);
    }

    #[test]
    fn issue_category_label_routes_data_exfil_to_dedicated_bucket() {
        // `taint-data-exfiltration` shares the `taint` family token with
        // `taint-unsanitised-flow`, but exfil findings need their own
        // dashboard badge so analysts can pivot on the leak class.
        assert_eq!(
            issue_category_label("taint-data-exfiltration"),
            "Data Exfiltration"
        );
        assert_eq!(
            issue_category_label("taint-data-exfiltration (source 1:1)"),
            "Data Exfiltration"
        );
        // Generic taint findings stay in the broader bucket.
        assert_eq!(
            issue_category_label("taint-unsanitised-flow"),
            "Tainted Flow"
        );
    }

    #[test]
    fn issue_category_label_recognises_simple_families() {
        assert_eq!(
            issue_category_label("js.xss.outer_html"),
            "Cross-Site Scripting"
        );
        assert_eq!(
            issue_category_label("py.cmdi.os_system"),
            "Command Injection"
        );
        assert_eq!(issue_category_label("garbage"), "Other");
    }
}
