use actix_web::{get, HttpResponse};

#[get("/users")]
async fn list_users() -> HttpResponse {
    HttpResponse::Ok().finish()
}
