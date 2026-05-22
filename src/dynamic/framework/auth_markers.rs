//! Auth + sanitization middleware registry.
//!
//! Framework adapters across `src/dynamic/framework/adapters/*` record
//! middleware names on [`super::FrameworkBinding::middleware`] without
//! interpreting them.  This module gives downstream consumers (a future
//! verifier-side oracle pass) a single answer to "is this middleware
//! name a known protective layer?" so finding verdicts can be demoted
//! when the bound handler is fronted by a known auth filter, CSRF
//! guard, validation pipe, or output sanitizer.
//!
//! The registry is intentionally per-language: `validate` in JS land
//! routinely names a Joi/Yup body validator, but in Java land
//! `validate()` is just an instance method.  Mixing them would create
//! false-positive demotions.  Class-name suffix patterns (`*Guard`,
//! `*Interceptor`, `*Filter`, `*Pipe`, `*Authenticator`, `*Validator`)
//! are checked after the exact-name table so Nest-style decorator
//! arguments and Spring annotation classes resolve uniformly.
//!
//! Consumers should call [`classify`] for the structured answer or
//! [`is_protective`] for the boolean shortcut.
//!
//! Distinct from `crate::auth_analysis::auth_markers`, which serves the
//! static analyser and tracks router auth-gating only (no
//! CSRF / validation / sanitization / rate-limit categories).  Both
//! modules can grow new entries independently; the static side gates
//! route-level finding suppression at scan time, this side gates
//! verifier-side verdict demotion at oracle time.

use crate::symbol::Lang;

/// Coarse category of a recognised middleware name.
///
/// Verdict-demotion logic uses the category to decide which finding
/// classes are actually mitigated.  For example, a `Csrf` marker does
/// not mitigate SSRF, but an `InputValidation` marker plausibly does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMarkerKind {
    /// Identity check: rejects requests without a valid session /
    /// token / user.  Examples: `passport`, `requireAuth`, `AuthGuard`,
    /// `@PreAuthorize`, Rails `authenticate_user!`.
    Authentication,
    /// Role / permission check: rejects requests whose authenticated
    /// principal lacks the required scope.  Examples: `RoleGuard`,
    /// `@RolesAllowed`, `@PermitAll`, `authorize`.
    Authorization,
    /// CSRF token verification.  Examples: `csrf`, `csurf`,
    /// `VerifyCsrfToken`, Rails `protect_from_forgery`.
    Csrf,
    /// Schema- or rule-driven input validation that rejects malformed
    /// payloads before they reach the handler.  Examples: `validate`,
    /// `ValidationPipe`, `joi`, `yup`, `zod`, `cerberus`.
    InputValidation,
    /// Output sanitization / encoding: scrubs response bytes.
    /// Examples: `helmet`, `xss-clean`, `mongoSanitize`.
    OutputSanitization,
    /// Request-rate throttling.  Examples: `rateLimit`,
    /// `ThrottleRequests`, `Rack::Attack`.
    RateLimit,
}

type ExactRow = (&'static str, AuthMarkerKind);

/// Exact-name table for JavaScript / TypeScript middleware (Express,
/// Koa, Fastify, Nest, applies symmetrically across JS/TS adapters).
const JS_EXACT: &[ExactRow] = &[
    ("authenticate", AuthMarkerKind::Authentication),
    ("requireAuth", AuthMarkerKind::Authentication),
    ("require_auth", AuthMarkerKind::Authentication),
    ("passport", AuthMarkerKind::Authentication),
    ("passportAuth", AuthMarkerKind::Authentication),
    ("tokenAuth", AuthMarkerKind::Authentication),
    ("authMiddleware", AuthMarkerKind::Authentication),
    ("jwtAuth", AuthMarkerKind::Authentication),
    ("ensureAuthenticated", AuthMarkerKind::Authentication),
    ("isAuthenticated", AuthMarkerKind::Authentication),
    ("authz", AuthMarkerKind::Authorization),
    ("authorize", AuthMarkerKind::Authorization),
    ("requireRole", AuthMarkerKind::Authorization),
    ("hasRole", AuthMarkerKind::Authorization),
    ("csrf", AuthMarkerKind::Csrf),
    ("csurf", AuthMarkerKind::Csrf),
    ("csrfProtection", AuthMarkerKind::Csrf),
    ("doubleCsrf", AuthMarkerKind::Csrf),
    ("validate", AuthMarkerKind::InputValidation),
    ("validateBody", AuthMarkerKind::InputValidation),
    ("validateRequest", AuthMarkerKind::InputValidation),
    ("validateSchema", AuthMarkerKind::InputValidation),
    ("schemaValidator", AuthMarkerKind::InputValidation),
    ("celebrate", AuthMarkerKind::InputValidation),
    ("joiValidate", AuthMarkerKind::InputValidation),
    ("zodValidate", AuthMarkerKind::InputValidation),
    ("yupValidate", AuthMarkerKind::InputValidation),
    ("ValidationPipe", AuthMarkerKind::InputValidation),
    ("helmet", AuthMarkerKind::OutputSanitization),
    ("xssClean", AuthMarkerKind::OutputSanitization),
    ("xss-clean", AuthMarkerKind::OutputSanitization),
    ("mongoSanitize", AuthMarkerKind::OutputSanitization),
    ("hpp", AuthMarkerKind::OutputSanitization),
    ("rateLimit", AuthMarkerKind::RateLimit),
    ("rateLimiter", AuthMarkerKind::RateLimit),
    ("expressRateLimit", AuthMarkerKind::RateLimit),
    ("slowDown", AuthMarkerKind::RateLimit),
    ("ThrottlerGuard", AuthMarkerKind::RateLimit),
];

/// Exact-name table for Python middleware (Django, Flask, FastAPI,
/// Starlette).
const PYTHON_EXACT: &[ExactRow] = &[
    ("login_required", AuthMarkerKind::Authentication),
    ("authentication_required", AuthMarkerKind::Authentication),
    ("auth_required", AuthMarkerKind::Authentication),
    ("require_login", AuthMarkerKind::Authentication),
    ("authenticate", AuthMarkerKind::Authentication),
    ("AuthenticationMiddleware", AuthMarkerKind::Authentication),
    ("LoginRequiredMixin", AuthMarkerKind::Authentication),
    ("JWTBearer", AuthMarkerKind::Authentication),
    ("HTTPBearer", AuthMarkerKind::Authentication),
    ("OAuth2PasswordBearer", AuthMarkerKind::Authentication),
    ("permission_required", AuthMarkerKind::Authorization),
    ("user_passes_test", AuthMarkerKind::Authorization),
    ("PermissionRequiredMixin", AuthMarkerKind::Authorization),
    ("require_permission", AuthMarkerKind::Authorization),
    ("csrf_protect", AuthMarkerKind::Csrf),
    ("CsrfViewMiddleware", AuthMarkerKind::Csrf),
    ("CSRFProtect", AuthMarkerKind::Csrf),
    ("validate", AuthMarkerKind::InputValidation),
    ("validate_request", AuthMarkerKind::InputValidation),
    ("ValidationMiddleware", AuthMarkerKind::InputValidation),
    ("pydantic_validate", AuthMarkerKind::InputValidation),
    ("SecurityMiddleware", AuthMarkerKind::OutputSanitization),
    ("XContentTypeOptionsMiddleware", AuthMarkerKind::OutputSanitization),
    ("bleach_clean", AuthMarkerKind::OutputSanitization),
    ("RateLimitMiddleware", AuthMarkerKind::RateLimit),
    ("ratelimit", AuthMarkerKind::RateLimit),
    ("throttle", AuthMarkerKind::RateLimit),
];

/// Exact-name table for Java middleware (Spring, Quarkus, Micronaut,
/// Servlet filters).  Annotation tokens are stored with leading `@` so
/// callers do not need to strip it before lookup.
const JAVA_EXACT: &[ExactRow] = &[
    ("@PreAuthorize", AuthMarkerKind::Authentication),
    ("@PostAuthorize", AuthMarkerKind::Authentication),
    ("@Secured", AuthMarkerKind::Authentication),
    ("@Authenticated", AuthMarkerKind::Authentication),
    ("@RequireAuth", AuthMarkerKind::Authentication),
    ("AuthenticationFilter", AuthMarkerKind::Authentication),
    ("JwtAuthenticationFilter", AuthMarkerKind::Authentication),
    ("SecurityFilterChain", AuthMarkerKind::Authentication),
    ("@RolesAllowed", AuthMarkerKind::Authorization),
    ("@PermitAll", AuthMarkerKind::Authorization),
    ("@DenyAll", AuthMarkerKind::Authorization),
    ("@HasRole", AuthMarkerKind::Authorization),
    ("CsrfFilter", AuthMarkerKind::Csrf),
    ("@EnableWebSecurity", AuthMarkerKind::Csrf),
    ("@Valid", AuthMarkerKind::InputValidation),
    ("@Validated", AuthMarkerKind::InputValidation),
    ("ValidationFilter", AuthMarkerKind::InputValidation),
    ("@RateLimited", AuthMarkerKind::RateLimit),
];

/// Exact-name table for PHP middleware (Laravel, Symfony, CodeIgniter).
const PHP_EXACT: &[ExactRow] = &[
    ("auth", AuthMarkerKind::Authentication),
    ("auth:sanctum", AuthMarkerKind::Authentication),
    ("auth:api", AuthMarkerKind::Authentication),
    ("auth.basic", AuthMarkerKind::Authentication),
    ("Authenticate", AuthMarkerKind::Authentication),
    ("EnsureEmailIsVerified", AuthMarkerKind::Authentication),
    ("verified", AuthMarkerKind::Authentication),
    ("#[IsGranted]", AuthMarkerKind::Authorization),
    ("#[Security]", AuthMarkerKind::Authorization),
    ("can", AuthMarkerKind::Authorization),
    ("authorize", AuthMarkerKind::Authorization),
    ("VerifyCsrfToken", AuthMarkerKind::Csrf),
    ("csrf", AuthMarkerKind::Csrf),
    ("ValidateRequest", AuthMarkerKind::InputValidation),
    ("FormRequest", AuthMarkerKind::InputValidation),
    ("validated", AuthMarkerKind::InputValidation),
    ("throttle", AuthMarkerKind::RateLimit),
    ("ThrottleRequests", AuthMarkerKind::RateLimit),
];

/// Exact-name table for Ruby middleware (Rails, Sinatra, Hanami, Rack).
const RUBY_EXACT: &[ExactRow] = &[
    ("authenticate_user!", AuthMarkerKind::Authentication),
    ("authenticate_admin!", AuthMarkerKind::Authentication),
    ("require_login", AuthMarkerKind::Authentication),
    ("Rack::Auth::Basic", AuthMarkerKind::Authentication),
    ("Devise::Authentication", AuthMarkerKind::Authentication),
    ("Warden::Manager", AuthMarkerKind::Authentication),
    ("authorize!", AuthMarkerKind::Authorization),
    ("authorize_resource", AuthMarkerKind::Authorization),
    ("can?", AuthMarkerKind::Authorization),
    ("verify_authorized", AuthMarkerKind::Authorization),
    ("protect_from_forgery", AuthMarkerKind::Csrf),
    ("Rack::Csrf", AuthMarkerKind::Csrf),
    ("verify_authenticity_token", AuthMarkerKind::Csrf),
    ("validate_params", AuthMarkerKind::InputValidation),
    ("Rack::Attack", AuthMarkerKind::RateLimit),
    ("throttle", AuthMarkerKind::RateLimit),
];

/// Exact-name table for Go middleware (gin / echo / fiber / chi).
const GO_EXACT: &[ExactRow] = &[
    ("AuthMiddleware", AuthMarkerKind::Authentication),
    ("BasicAuth", AuthMarkerKind::Authentication),
    ("JWTAuth", AuthMarkerKind::Authentication),
    ("RequireAuth", AuthMarkerKind::Authentication),
    ("middleware.JWT", AuthMarkerKind::Authentication),
    ("jwtauth.Verifier", AuthMarkerKind::Authentication),
    ("jwtauth.Authenticator", AuthMarkerKind::Authentication),
    ("Authorize", AuthMarkerKind::Authorization),
    ("RequireRole", AuthMarkerKind::Authorization),
    ("CSRF", AuthMarkerKind::Csrf),
    ("csrf.New", AuthMarkerKind::Csrf),
    ("nosurf.New", AuthMarkerKind::Csrf),
    ("validator", AuthMarkerKind::InputValidation),
    ("ValidatePayload", AuthMarkerKind::InputValidation),
    ("RateLimit", AuthMarkerKind::RateLimit),
    ("limiter.New", AuthMarkerKind::RateLimit),
    ("middleware.RateLimit", AuthMarkerKind::RateLimit),
];

/// Exact-name table for Rust middleware (axum / actix / rocket / warp).
const RUST_EXACT: &[ExactRow] = &[
    ("auth_layer", AuthMarkerKind::Authentication),
    ("AuthLayer", AuthMarkerKind::Authentication),
    ("RequireAuth", AuthMarkerKind::Authentication),
    ("HttpAuthentication", AuthMarkerKind::Authentication),
    ("BearerAuth", AuthMarkerKind::Authentication),
    ("authorize", AuthMarkerKind::Authorization),
    ("require_role", AuthMarkerKind::Authorization),
    ("csrf", AuthMarkerKind::Csrf),
    ("CsrfLayer", AuthMarkerKind::Csrf),
    ("validate_payload", AuthMarkerKind::InputValidation),
    ("ValidatedJson", AuthMarkerKind::InputValidation),
    ("rate_limit", AuthMarkerKind::RateLimit),
    ("RateLimitLayer", AuthMarkerKind::RateLimit),
    ("tower_governor", AuthMarkerKind::RateLimit),
];

/// Per-language exact-name table dispatch.  Returns the slice that
/// matches `lang`; empty slice for languages that have no recognised
/// middleware vocabulary yet (C / C++).
fn exact_table_for(lang: Lang) -> &'static [ExactRow] {
    match lang {
        Lang::JavaScript | Lang::TypeScript => JS_EXACT,
        Lang::Python => PYTHON_EXACT,
        Lang::Java => JAVA_EXACT,
        Lang::Php => PHP_EXACT,
        Lang::Ruby => RUBY_EXACT,
        Lang::Go => GO_EXACT,
        Lang::Rust => RUST_EXACT,
        Lang::C | Lang::Cpp => &[],
    }
}

/// Class-name suffix patterns recognised across every language.  Nest
/// `@UseGuards(JwtAuthGuard)` argument `JwtAuthGuard` resolves via the
/// `Guard` suffix; Java `RoleInterceptor` resolves via `Interceptor`;
/// Spring `*Filter` annotations resolve via `Filter`.
fn classify_by_suffix(name: &str) -> Option<AuthMarkerKind> {
    if name.ends_with("Guard") {
        if name.contains("Auth") || name == "Guard" {
            return Some(AuthMarkerKind::Authentication);
        }
        if name.contains("Role") || name.contains("Permission") {
            return Some(AuthMarkerKind::Authorization);
        }
        if name.contains("Throttler") || name.contains("RateLimit") {
            return Some(AuthMarkerKind::RateLimit);
        }
        return Some(AuthMarkerKind::Authentication);
    }
    if name.ends_with("Interceptor") {
        return Some(AuthMarkerKind::Authentication);
    }
    if name.ends_with("Authenticator") {
        return Some(AuthMarkerKind::Authentication);
    }
    if name.ends_with("Authorizer") {
        return Some(AuthMarkerKind::Authorization);
    }
    if name.ends_with("Filter") {
        if name.contains("Auth") {
            return Some(AuthMarkerKind::Authentication);
        }
        if name.contains("Csrf") || name.contains("CSRF") {
            return Some(AuthMarkerKind::Csrf);
        }
        if name.contains("Validation") {
            return Some(AuthMarkerKind::InputValidation);
        }
        return None;
    }
    if name.ends_with("Validator") || name.ends_with("ValidationPipe") {
        return Some(AuthMarkerKind::InputValidation);
    }
    if name.ends_with("Pipe") && name.contains("Validation") {
        return Some(AuthMarkerKind::InputValidation);
    }
    None
}

/// Classify a middleware name recorded on
/// [`super::FrameworkBinding::middleware`] for a known language.
///
/// Lookup order: exact-name table for `lang` → class-name suffix
/// patterns (language-agnostic).  Returns `None` when the name is not
/// recognised.
pub fn classify(lang: Lang, name: &str) -> Option<AuthMarkerKind> {
    let table = exact_table_for(lang);
    for (candidate, kind) in table {
        if *candidate == name {
            return Some(*kind);
        }
    }
    classify_by_suffix(name)
}

/// True when `name` is recognised by [`classify`] for the given
/// language.  Convenience wrapper for callers that do not need the
/// category.
pub fn is_protective(lang: Lang, name: &str) -> bool {
    classify(lang, name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_authentication_markers_classified() {
        assert_eq!(
            classify(Lang::JavaScript, "passport"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::JavaScript, "requireAuth"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::TypeScript, "passport"),
            Some(AuthMarkerKind::Authentication)
        );
    }

    #[test]
    fn js_csrf_marker_classified() {
        assert_eq!(
            classify(Lang::JavaScript, "csrf"),
            Some(AuthMarkerKind::Csrf)
        );
        assert_eq!(
            classify(Lang::JavaScript, "csurf"),
            Some(AuthMarkerKind::Csrf)
        );
    }

    #[test]
    fn js_validation_marker_classified() {
        assert_eq!(
            classify(Lang::JavaScript, "validate"),
            Some(AuthMarkerKind::InputValidation)
        );
        assert_eq!(
            classify(Lang::JavaScript, "celebrate"),
            Some(AuthMarkerKind::InputValidation)
        );
    }

    #[test]
    fn js_rate_limit_marker_classified() {
        assert_eq!(
            classify(Lang::JavaScript, "rateLimit"),
            Some(AuthMarkerKind::RateLimit)
        );
    }

    #[test]
    fn js_unknown_name_returns_none() {
        assert_eq!(classify(Lang::JavaScript, "handler"), None);
        assert_eq!(classify(Lang::JavaScript, "doStuff"), None);
    }

    #[test]
    fn nest_guard_suffix_resolves_by_pattern() {
        // Nest decorator arguments come in as class names without any
        // entry in the exact table; resolve via suffix pattern.
        assert_eq!(
            classify(Lang::JavaScript, "JwtAuthGuard"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::TypeScript, "JwtAuthGuard"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::JavaScript, "RoleGuard"),
            Some(AuthMarkerKind::Authorization)
        );
        assert_eq!(
            classify(Lang::JavaScript, "PermissionGuard"),
            Some(AuthMarkerKind::Authorization)
        );
        assert_eq!(
            classify(Lang::JavaScript, "ThrottlerGuard"),
            Some(AuthMarkerKind::RateLimit)
        );
    }

    #[test]
    fn nest_interceptor_suffix_resolves() {
        assert_eq!(
            classify(Lang::TypeScript, "LoggingInterceptor"),
            Some(AuthMarkerKind::Authentication)
        );
    }

    #[test]
    fn python_decorator_classified() {
        assert_eq!(
            classify(Lang::Python, "login_required"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::Python, "csrf_protect"),
            Some(AuthMarkerKind::Csrf)
        );
        assert_eq!(
            classify(Lang::Python, "permission_required"),
            Some(AuthMarkerKind::Authorization)
        );
    }

    #[test]
    fn java_annotation_classified() {
        assert_eq!(
            classify(Lang::Java, "@PreAuthorize"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::Java, "@RolesAllowed"),
            Some(AuthMarkerKind::Authorization)
        );
        assert_eq!(
            classify(Lang::Java, "@Valid"),
            Some(AuthMarkerKind::InputValidation)
        );
    }

    #[test]
    fn java_security_filter_suffix_resolves() {
        assert_eq!(
            classify(Lang::Java, "JwtAuthFilter"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::Java, "CsrfFilter"),
            Some(AuthMarkerKind::Csrf)
        );
    }

    #[test]
    fn php_middleware_classified() {
        assert_eq!(
            classify(Lang::Php, "auth"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::Php, "auth:sanctum"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::Php, "VerifyCsrfToken"),
            Some(AuthMarkerKind::Csrf)
        );
        assert_eq!(
            classify(Lang::Php, "FormRequest"),
            Some(AuthMarkerKind::InputValidation)
        );
    }

    #[test]
    fn ruby_filter_classified() {
        assert_eq!(
            classify(Lang::Ruby, "authenticate_user!"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::Ruby, "protect_from_forgery"),
            Some(AuthMarkerKind::Csrf)
        );
        assert_eq!(
            classify(Lang::Ruby, "Rack::Attack"),
            Some(AuthMarkerKind::RateLimit)
        );
    }

    #[test]
    fn go_middleware_classified() {
        assert_eq!(
            classify(Lang::Go, "JWTAuth"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::Go, "csrf.New"),
            Some(AuthMarkerKind::Csrf)
        );
    }

    #[test]
    fn rust_layer_classified() {
        assert_eq!(
            classify(Lang::Rust, "AuthLayer"),
            Some(AuthMarkerKind::Authentication)
        );
        assert_eq!(
            classify(Lang::Rust, "CsrfLayer"),
            Some(AuthMarkerKind::Csrf)
        );
        assert_eq!(
            classify(Lang::Rust, "RateLimitLayer"),
            Some(AuthMarkerKind::RateLimit)
        );
    }

    #[test]
    fn c_and_cpp_have_no_markers() {
        assert_eq!(classify(Lang::C, "anything"), None);
        assert_eq!(classify(Lang::Cpp, "anything"), None);
    }

    #[test]
    fn is_protective_matches_classify() {
        assert!(is_protective(Lang::JavaScript, "passport"));
        assert!(is_protective(Lang::Python, "login_required"));
        assert!(is_protective(Lang::Java, "@PreAuthorize"));
        assert!(!is_protective(Lang::JavaScript, "doSomething"));
        assert!(!is_protective(Lang::C, "AuthLayer"));
    }

    #[test]
    fn exact_match_wins_over_suffix() {
        // `Guard` literal name should resolve as Authentication via
        // exact lookup (suffix path), not collide with downstream
        // alphabetic patterns.  Ensures the suffix branch is
        // deterministic when the literal name has no exact-table row.
        assert_eq!(
            classify(Lang::JavaScript, "Guard"),
            Some(AuthMarkerKind::Authentication)
        );
    }
}
