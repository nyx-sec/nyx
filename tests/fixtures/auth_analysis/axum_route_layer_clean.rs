use axum::{
    Router,
    extract::{Path, State},
    middleware,
    routing::delete,
};

fn require_admin() {}
fn require_doc_owner() {}

async fn remove_layered_user(Path(user_id): Path<String>, State(db): State<Db>) {
    db.delete_user(&user_id).await;
}

async fn remove_layered_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

fn layered_router() -> Router {
    Router::new()
        .route("/admin/users/:user_id", delete(remove_layered_user))
        .route_layer(middleware::from_fn(require_admin))
        .route("/docs/:doc_id", delete(remove_layered_doc))
        .route_layer(middleware::from_fn(require_doc_owner))
}
