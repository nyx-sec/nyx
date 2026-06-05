//! Middleware-aware verdict demotion (Phase 13 verifier-consumer pass).
//!
//! The dynamic verifier's differential rule produces a
//! [`DifferentialVerdict`] in two flavours that survive the loop:
//! [`DifferentialVerdict::Confirmed`] (vuln fires, benign does not) and
//! [`DifferentialVerdict::ConfirmedProvenOob`] (vuln fires + OOB nonce
//! callback observed).  Either outcome is positive evidence the sink ran,
//! but says nothing about whether the surrounding application carries a
//! known protective layer.
//!
//! Framework adapters (`src/dynamic/framework/adapters/*`) populate
//! [`FrameworkBinding::middleware`] with the names of every middleware /
//! decorator / interceptor / filter recorded at adapter time.  The
//! [`crate::dynamic::framework::auth_markers`] registry then classifies
//! each name into a coarse category.  Only `InputValidation` and
//! `OutputSanitization` actually mitigate injection sinks: an
//! authentication check rejects requests without a valid principal but
//! does not sanitize the request bytes; a CSRF guard does not stop SSRF;
//! a rate limiter or broker dead-letter/error/visibility policy changes
//! delivery semantics but not payload safety.  So the demotion rule is
//! tight: a `Confirmed`/`ConfirmedProvenOob` verdict whose binding's
//! middleware vec contains at least one `InputValidation` or
//! `OutputSanitization` entry is downgraded to
//! [`DifferentialVerdict::ConfirmedWithKnownGuard`].  Every other
//! category leaves the verdict untouched.
//!
//! Demote, do not suppress: the verdict stays Confirmed-class so the
//! verifier still trips the loop break and emits
//! [`crate::evidence::VerifyStatus::Confirmed`].  Operators see the
//! guard names on [`DifferentialOutcome::known_guards`] and can
//! deprioritise the finding without losing the underlying signal.

use crate::dynamic::framework::FrameworkBinding;
use crate::dynamic::framework::auth_markers::{AuthMarkerKind, classify};
use crate::evidence::{DifferentialOutcome, DifferentialVerdict};
use crate::symbol::Lang;

/// Apply middleware-aware verdict demotion to a finalised
/// [`DifferentialOutcome`] in place.
///
/// When the outcome's verdict is `Confirmed` or `ConfirmedProvenOob` and
/// `binding.middleware` contains at least one entry that
/// [`classify`] resolves to `InputValidation` or `OutputSanitization`,
/// the verdict is downgraded to `ConfirmedWithKnownGuard` and the
/// matched middleware names are appended to
/// [`DifferentialOutcome::known_guards`] in declaration order.
///
/// Returns the demoting category list so callers can inspect what
/// drove the decision; the list is empty when no demotion was
/// applied.
pub fn apply_demotion(
    outcome: &mut DifferentialOutcome,
    binding: Option<&FrameworkBinding>,
    lang: Lang,
) -> Vec<AuthMarkerKind> {
    if !is_confirmed_class(outcome.verdict) {
        return Vec::new();
    }
    let Some(binding) = binding else {
        return Vec::new();
    };
    if binding.middleware.is_empty() {
        return Vec::new();
    }
    let mut demoting_kinds: Vec<AuthMarkerKind> = Vec::new();
    let mut demoting_names: Vec<String> = Vec::new();
    for mw in &binding.middleware {
        if let Some(kind) = classify(lang, &mw.name)
            && is_demoting_category(kind)
        {
            demoting_kinds.push(kind);
            demoting_names.push(mw.name.clone());
        }
    }
    if demoting_kinds.is_empty() {
        return Vec::new();
    }
    outcome.verdict = DifferentialVerdict::ConfirmedWithKnownGuard;
    outcome.known_guards.extend(demoting_names);
    demoting_kinds
}

/// True when `verdict` is a Confirmed-class outcome eligible for
/// demotion.  `ConfirmedWithKnownGuard` is intentionally excluded so a
/// second pass cannot re-demote (idempotent).
pub fn is_confirmed_class(verdict: DifferentialVerdict) -> bool {
    matches!(
        verdict,
        DifferentialVerdict::Confirmed | DifferentialVerdict::ConfirmedProvenOob
    )
}

/// True when the category actually mitigates injection sinks.  Only
/// `InputValidation` and `OutputSanitization` qualify; authentication /
/// authorization rejects unauthorised callers but does not sanitize the
/// bytes the caller sends, CSRF protects against cross-origin abuse,
/// and rate limiting / broker-runtime guards throttle or reroute rather
/// than scrub.
fn is_demoting_category(kind: AuthMarkerKind) -> bool {
    matches!(
        kind,
        AuthMarkerKind::InputValidation | AuthMarkerKind::OutputSanitization
    )
}

/// True when the demoted verdict is still positive evidence the sink
/// ran.  Used by the runner so the loop break and `triggered_by` semantics
/// stay aligned with the original Confirmed-class set.
pub fn is_triggering_verdict(verdict: DifferentialVerdict) -> bool {
    matches!(
        verdict,
        DifferentialVerdict::Confirmed
            | DifferentialVerdict::ConfirmedProvenOob
            | DifferentialVerdict::ConfirmedWithKnownGuard
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::{FrameworkBinding, HttpMethod, MiddlewareShape, RouteShape};
    use crate::evidence::EntryKind;

    fn make_outcome(verdict: DifferentialVerdict) -> DifferentialOutcome {
        DifferentialOutcome {
            verdict,
            vuln_label: "vuln".to_string(),
            benign_label: "benign".to_string(),
            vuln_probes: Vec::new(),
            benign_probes: Vec::new(),
            known_guards: Vec::new(),
        }
    }

    fn make_binding(middleware: Vec<&str>) -> FrameworkBinding {
        FrameworkBinding {
            adapter: "test-adapter".to_string(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape::single(HttpMethod::GET, "/x")),
            request_params: Vec::new(),
            response_writer: None,
            middleware: middleware
                .into_iter()
                .map(|name| MiddlewareShape {
                    name: name.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn no_binding_leaves_verdict_unchanged() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let kinds = apply_demotion(&mut outcome, None, Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
        assert!(outcome.known_guards.is_empty());
    }

    #[test]
    fn empty_middleware_leaves_verdict_unchanged() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(Vec::new());
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn unknown_middleware_leaves_verdict_unchanged() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["handler", "doStuff", "logRequest"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
        assert!(outcome.known_guards.is_empty());
    }

    #[test]
    fn authentication_alone_does_not_demote() {
        // Auth checks reject unauthorized callers but do not sanitize
        // the request bytes — they cannot mitigate SQL injection or
        // command injection.  Verdict stays Confirmed.
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["passport", "requireAuth"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
        assert!(outcome.known_guards.is_empty());
    }

    #[test]
    fn authorization_alone_does_not_demote() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["authorize", "requireRole"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn csrf_alone_does_not_demote() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["csrf"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn rate_limit_alone_does_not_demote() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["rateLimit"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn broker_runtime_guards_do_not_demote() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec![
            "visibilityTimeout",
            "deadLetterQueue",
            "errorHandler",
            "queueGroup",
        ]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
        assert!(outcome.known_guards.is_empty());
    }

    #[test]
    fn input_validation_demotes_confirmed() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["validate"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert_eq!(kinds, vec![AuthMarkerKind::InputValidation]);
        assert_eq!(
            outcome.verdict,
            DifferentialVerdict::ConfirmedWithKnownGuard
        );
        assert_eq!(outcome.known_guards, vec!["validate".to_string()]);
    }

    #[test]
    fn output_sanitization_demotes_confirmed() {
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["helmet"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert_eq!(kinds, vec![AuthMarkerKind::OutputSanitization]);
        assert_eq!(
            outcome.verdict,
            DifferentialVerdict::ConfirmedWithKnownGuard
        );
        assert_eq!(outcome.known_guards, vec!["helmet".to_string()]);
    }

    #[test]
    fn proven_oob_can_also_be_demoted() {
        let mut outcome = make_outcome(DifferentialVerdict::ConfirmedProvenOob);
        let binding = make_binding(vec!["validate"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert_eq!(kinds, vec![AuthMarkerKind::InputValidation]);
        assert_eq!(
            outcome.verdict,
            DifferentialVerdict::ConfirmedWithKnownGuard
        );
    }

    #[test]
    fn mixed_middleware_picks_only_protective_names() {
        // Auth + Validation: only Validation drives the demotion, but
        // the guard list captures the matched name.  Auth name does
        // not land in the guard list.
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["passport", "validate", "rateLimit", "helmet"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert_eq!(
            kinds,
            vec![
                AuthMarkerKind::InputValidation,
                AuthMarkerKind::OutputSanitization,
            ]
        );
        assert_eq!(
            outcome.verdict,
            DifferentialVerdict::ConfirmedWithKnownGuard
        );
        assert_eq!(
            outcome.known_guards,
            vec!["validate".to_string(), "helmet".to_string()]
        );
    }

    #[test]
    fn not_confirmed_does_not_demote() {
        let mut outcome = make_outcome(DifferentialVerdict::NotConfirmed);
        let binding = make_binding(vec!["validate"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::NotConfirmed);
        assert!(outcome.known_guards.is_empty());
    }

    #[test]
    fn collision_does_not_demote() {
        let mut outcome = make_outcome(DifferentialVerdict::OracleCollisionSuspected);
        let binding = make_binding(vec!["validate"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(
            outcome.verdict,
            DifferentialVerdict::OracleCollisionSuspected
        );
    }

    #[test]
    fn reversed_differential_does_not_demote() {
        let mut outcome = make_outcome(DifferentialVerdict::ReversedDifferential);
        let binding = make_binding(vec!["validate"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::ReversedDifferential);
    }

    #[test]
    fn second_pass_is_idempotent() {
        // Once demoted, a re-application must not append duplicate
        // guards or further change the verdict.
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["validate"]);
        apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        let kinds_second = apply_demotion(&mut outcome, Some(&binding), Lang::JavaScript);
        assert!(kinds_second.is_empty());
        assert_eq!(
            outcome.verdict,
            DifferentialVerdict::ConfirmedWithKnownGuard
        );
        assert_eq!(outcome.known_guards, vec!["validate".to_string()]);
    }

    #[test]
    fn nest_validation_pipe_suffix_demotes() {
        // Nest's `ValidationPipe` is an exact-table entry but the
        // suffix-pattern path also recognises any `*ValidationPipe`
        // name via auth_markers.  Both shapes must demote.
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["BodyValidationPipe"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::TypeScript);
        assert_eq!(kinds, vec![AuthMarkerKind::InputValidation]);
        assert_eq!(
            outcome.verdict,
            DifferentialVerdict::ConfirmedWithKnownGuard
        );
    }

    #[test]
    fn cross_language_dispatch_respects_lang_param() {
        // `validate` resolves under JS but not under C (where no exact
        // table exists and the suffix patterns do not match).
        let mut outcome = make_outcome(DifferentialVerdict::Confirmed);
        let binding = make_binding(vec!["validate"]);
        let kinds = apply_demotion(&mut outcome, Some(&binding), Lang::C);
        assert!(kinds.is_empty());
        assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn is_triggering_verdict_covers_guarded_variant() {
        assert!(is_triggering_verdict(DifferentialVerdict::Confirmed));
        assert!(is_triggering_verdict(
            DifferentialVerdict::ConfirmedProvenOob
        ));
        assert!(is_triggering_verdict(
            DifferentialVerdict::ConfirmedWithKnownGuard
        ));
        assert!(!is_triggering_verdict(DifferentialVerdict::NotConfirmed));
        assert!(!is_triggering_verdict(
            DifferentialVerdict::OracleCollisionSuspected
        ));
        assert!(!is_triggering_verdict(
            DifferentialVerdict::ReversedDifferential
        ));
    }
}
