use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct Upstream {
    status: String,
}

async fn proxy_status(req: HttpRequest, body: web::Bytes) -> Result<HttpResponse, reqwest::Error> {
    let client = reqwest::Client::new();
    let res = client
        .post("https://status.internal.example.com/v1/check")
        .header("x-request-id", req.headers().len().to_string())
        .body(body.to_vec())
        .send()
        .await?;
    let upstream = res.json::<Upstream>().await?;
    Ok(HttpResponse::Ok().body(upstream.status.len().to_string()))
}
