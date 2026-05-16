//! Canonical per-framework authentication-marker registry.
//!
//! Both the Phase 22 surface probes (`src/surface/lang/*.rs`) and the
//! auth-analysis recogniser consult this module so a marker that is
//! known to one side cannot drift away from the other. Each constant
//! is a flat `&[&str]` of identifier shapes that signal a route is
//! gated behind authentication; surface probes match the leaf segment
//! of a decorator / middleware / extractor identifier
//! (case-insensitive), and the auth analyser folds these into its
//! per-language `login_guard_names` / `authorization_check_names`
//! tables via [`router_auth_markers_for_lang`].
//!
//! The lists were lifted verbatim from the per-probe constants that
//! shipped with Phase 22; further additions land here and propagate to
//! every consumer at once.
//!
//! Lookups: prefer [`is_router_auth_marker`] for the framework-aware
//! dispatch, fall back to [`is_known_router_auth_marker`] when the
//! framework is not yet identified at the call site.

use crate::symbol::Lang;

/// Frameworks the surface probes recognise. Distinct from
/// [`crate::surface::Framework`] (which carries pretty-print metadata)
/// so this module stays free of surface-layer types and can be
/// imported by `auth_analysis::extract` without a circular dep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthFramework {
    Flask,
    FastApi,
    Django,
    Spring,
    JavaServlet,
    Quarkus,
    Express,
    Koa,
    Gin,
    ActixWeb,
    Axum,
}

/// Flask (`@login_required`, `@requires_auth`, …).
pub const FLASK_DECORATORS: &[&str] = &[
    "login_required",
    "auth_required",
    "jwt_required",
    "token_required",
    "requires_auth",
    "authenticated",
    "require_login",
];

/// FastAPI (`Depends(get_current_user)`, `@login_required`, …).
pub const FASTAPI_DECORATORS: &[&str] = &[
    "login_required",
    "auth_required",
    "jwt_required",
    "token_required",
    "requires_auth",
    "authenticated",
    "require_auth",
    "require_login",
    "current_user",
];

/// Django (`@login_required`, `@permission_required`, …).
pub const DJANGO_DECORATORS: &[&str] = &[
    "login_required",
    "permission_required",
    "user_passes_test",
    "staff_member_required",
    "csrf_protect",
    "require_authenticated",
    "auth_required",
];

/// Spring (`@PreAuthorize`, `@Secured`, …).
pub const SPRING_ANNOTATIONS: &[&str] = &[
    "PreAuthorize",
    "PostAuthorize",
    "Secured",
    "RolesAllowed",
    "AuthenticationPrincipal",
];

/// Java Servlet / JAX-RS (`@RolesAllowed`, `@RequiresAuthentication`, …).
pub const SERVLET_ANNOTATIONS: &[&str] = &[
    "RolesAllowed",
    "DenyAll",
    "RequiresAuthentication",
    "RequiresUser",
];

/// Quarkus (`@Authenticated`, `@RolesAllowed`, …).
pub const QUARKUS_ANNOTATIONS: &[&str] = &[
    "Authenticated",
    "RolesAllowed",
    "DenyAll",
    "RequiresAuthentication",
];

/// Express middleware (`app.use(requireAuth)`, `passport.authenticate`, …).
pub const EXPRESS_MIDDLEWARES: &[&str] = &[
    "requireAuth",
    "requireUser",
    "isAuthenticated",
    "ensureAuthenticated",
    "ensureLoggedIn",
    "authenticate",
    "authMiddleware",
    "verifyToken",
    "verifyJwt",
    "checkJwt",
    "passport",
    "jwt",
];

/// Koa middleware.
pub const KOA_MIDDLEWARES: &[&str] = &[
    "requireAuth",
    "requireUser",
    "isAuthenticated",
    "ensureAuthenticated",
    "authenticate",
    "authMiddleware",
    "verifyToken",
    "verifyJwt",
    "checkJwt",
    "passport",
    "jwt",
    "koaJwt",
];

/// Gin middleware (`router.Use(AuthRequired())`, `jwt.JWT()`, …).
pub const GIN_MIDDLEWARES: &[&str] = &[
    "AuthRequired",
    "JWT",
    "JWTAuth",
    "Auth",
    "RequireAuth",
    "RequireUser",
    "VerifyToken",
    "BasicAuth",
];

/// actix-web extractors (`Identity`, `BearerAuth`, …).
pub const ACTIX_EXTRACTORS: &[&str] = &[
    "Identity",
    "BearerAuth",
    "BasicAuth",
    "JwtClaims",
    "Authenticated",
    "User",
];

/// axum extractors (`Extension<User>`, `BearerAuth`, …).
pub const AXUM_EXTRACTORS: &[&str] = &[
    "Extension<User",
    "BearerAuth",
    "RequireAuth",
    "AuthenticatedUser",
    "JwtClaims",
];

/// Per-framework marker list. Returns the empty slice when the
/// framework is not registered yet.
pub fn markers_for(framework: AuthFramework) -> &'static [&'static str] {
    match framework {
        AuthFramework::Flask => FLASK_DECORATORS,
        AuthFramework::FastApi => FASTAPI_DECORATORS,
        AuthFramework::Django => DJANGO_DECORATORS,
        AuthFramework::Spring => SPRING_ANNOTATIONS,
        AuthFramework::JavaServlet => SERVLET_ANNOTATIONS,
        AuthFramework::Quarkus => QUARKUS_ANNOTATIONS,
        AuthFramework::Express => EXPRESS_MIDDLEWARES,
        AuthFramework::Koa => KOA_MIDDLEWARES,
        AuthFramework::Gin => GIN_MIDDLEWARES,
        AuthFramework::ActixWeb => ACTIX_EXTRACTORS,
        AuthFramework::Axum => AXUM_EXTRACTORS,
    }
}

/// Case-insensitive whole-string match against the per-framework list.
pub fn is_router_auth_marker(framework: AuthFramework, marker: &str) -> bool {
    let m = marker.trim();
    markers_for(framework)
        .iter()
        .any(|cand| cand.eq_ignore_ascii_case(m))
}

/// Loose match against every framework's list. Used when the call
/// site has the language but not the specific framework — e.g. an
/// auth-analyser folding "is this a known router-level guard?" into a
/// per-language ruleset where the framework split is opaque.
pub fn is_known_router_auth_marker(marker: &str) -> bool {
    let m = marker.trim();
    [
        FLASK_DECORATORS,
        FASTAPI_DECORATORS,
        DJANGO_DECORATORS,
        SPRING_ANNOTATIONS,
        SERVLET_ANNOTATIONS,
        QUARKUS_ANNOTATIONS,
        EXPRESS_MIDDLEWARES,
        KOA_MIDDLEWARES,
        GIN_MIDDLEWARES,
        ACTIX_EXTRACTORS,
        AXUM_EXTRACTORS,
    ]
    .iter()
    .any(|list| list.iter().any(|cand| cand.eq_ignore_ascii_case(m)))
}

/// Every router-auth marker the canonical registry knows for `lang`.
/// Used by `auth_analysis::config::default_for` to seed
/// `login_guard_names` so a marker added here propagates into the
/// per-language guard list without a second edit.
pub fn router_auth_markers_for_lang(lang: Lang) -> Vec<&'static str> {
    let lists: &[&[&str]] = match lang {
        Lang::Python => &[FLASK_DECORATORS, FASTAPI_DECORATORS, DJANGO_DECORATORS],
        Lang::Java => &[SPRING_ANNOTATIONS, SERVLET_ANNOTATIONS, QUARKUS_ANNOTATIONS],
        Lang::JavaScript | Lang::TypeScript => &[EXPRESS_MIDDLEWARES, KOA_MIDDLEWARES],
        Lang::Go => &[GIN_MIDDLEWARES],
        Lang::Rust => &[ACTIX_EXTRACTORS, AXUM_EXTRACTORS],
        _ => &[],
    };
    let mut out: Vec<&'static str> = lists.iter().flat_map(|l| l.iter().copied()).collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flask_login_required_resolves_case_insensitively() {
        assert!(is_router_auth_marker(AuthFramework::Flask, "login_required"));
        assert!(is_router_auth_marker(AuthFramework::Flask, "Login_Required"));
        assert!(!is_router_auth_marker(AuthFramework::Flask, "something_else"));
    }

    #[test]
    fn spring_preauthorize_resolves() {
        assert!(is_router_auth_marker(AuthFramework::Spring, "PreAuthorize"));
        assert!(!is_router_auth_marker(AuthFramework::Spring, "GetMapping"));
    }

    #[test]
    fn known_marker_matches_across_frameworks() {
        // `RolesAllowed` shows up in Spring, Servlet, and Quarkus —
        // the framework-agnostic helper finds it regardless.
        assert!(is_known_router_auth_marker("RolesAllowed"));
        assert!(is_known_router_auth_marker("login_required"));
        assert!(!is_known_router_auth_marker("not_an_auth_marker_xyz"));
    }

    #[test]
    fn python_router_markers_cover_every_framework() {
        let markers = router_auth_markers_for_lang(Lang::Python);
        for &decorator in FLASK_DECORATORS {
            assert!(markers.contains(&decorator), "missing flask: {decorator}");
        }
        for &decorator in FASTAPI_DECORATORS {
            assert!(markers.contains(&decorator), "missing fastapi: {decorator}");
        }
        for &decorator in DJANGO_DECORATORS {
            assert!(markers.contains(&decorator), "missing django: {decorator}");
        }
    }

    #[test]
    fn router_markers_for_unknown_lang_is_empty() {
        assert!(router_auth_markers_for_lang(Lang::Ruby).is_empty());
        assert!(router_auth_markers_for_lang(Lang::Php).is_empty());
    }
}
