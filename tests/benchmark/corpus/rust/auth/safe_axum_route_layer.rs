// `route_layer` wraps the routes added before it, so the owner layer at the
// end covers both routes and the admin layer covers the first.
use axum::{
    Router,
    extract::{Path, State},
    middleware,
    routing::delete,
};

fn require_admin() {}
fn require_doc_owner() {}

async fn remove_user(Path(user_id): Path<String>, State(db): State<Db>) {
    db.delete_user(&user_id).await;
}

async fn remove_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

fn router() -> Router {
    Router::new()
        .route("/admin/users/:user_id", delete(remove_user))
        .route_layer(middleware::from_fn(require_admin))
        .route("/docs/:doc_id", delete(remove_doc))
        .route_layer(middleware::from_fn(require_doc_owner))
}
