use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

static INDEX_HTML: &str = include_str!("assets/dist/index.html");
static STYLE_CSS: &str = include_str!("assets/dist/style.css");
static APP_JS: &str = include_str!("assets/dist/app.js");
static FAVICON_SVG: &str = include_str!("assets/favicon.svg");
static FAVICON_32: &[u8] = include_bytes!("assets/favicon-32.png");
static FAVICON_64: &[u8] = include_bytes!("assets/favicon-64.png");
static FAVICON_180: &[u8] = include_bytes!("assets/favicon-180.png");
static LOGO_PNG: &[u8] = include_bytes!("assets/logo.png");

/// Serve embedded static files or fall back to the SPA shell.
pub async fn static_handler(req: Request) -> Response {
    let path = req.uri().path();

    match path {
        "/style.css" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
            STYLE_CSS,
        )
            .into_response(),
        "/app.js" => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            )],
            APP_JS,
        )
            .into_response(),
        "/favicon.svg" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "image/svg+xml")],
            FAVICON_SVG,
        )
            .into_response(),
        "/favicon-32.png" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "image/png")],
            FAVICON_32,
        )
            .into_response(),
        "/favicon-64.png" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "image/png")],
            FAVICON_64,
        )
            .into_response(),
        "/favicon-180.png" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "image/png")],
            FAVICON_180,
        )
            .into_response(),
        "/logo.png" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "image/png")],
            LOGO_PNG,
        )
            .into_response(),
        // SPA fallback: any non-API path serves index.html.
        _ => Html(INDEX_HTML).into_response(),
    }
}
