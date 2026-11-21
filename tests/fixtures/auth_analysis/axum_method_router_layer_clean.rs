use axum::{
    Router,
    extract::{Path, State},
    middleware,
    routing::delete,
};

fn require_doc_owner() {}

async fn remove_method_layered_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

fn method_layered_router() -> Router {
    Router::new().route(
        "/docs/:doc_id",
        delete(remove_method_layered_doc).route_layer(middleware::from_fn(require_doc_owner)),
    )
}
