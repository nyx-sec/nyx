use axum::{
    Router,
    extract::{Path, State},
    middleware,
    routing::delete,
};

fn require_doc_owner() {}

async fn remove_unlayered_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

// `layer` wraps the routes added before it, and there are none yet.
fn early_layer_router() -> Router {
    Router::new()
        .layer(middleware::from_fn(require_doc_owner))
        .route("/docs/:doc_id", delete(remove_unlayered_doc))
}
