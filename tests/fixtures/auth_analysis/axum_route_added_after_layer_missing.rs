use axum::{
    Router,
    extract::{Path, State},
    middleware,
    routing::delete,
};

fn require_doc_owner() {}

async fn remove_covered_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

async fn remove_uncovered_note(Path(note_id): Path<String>, State(db): State<Db>) {
    db.delete_note(&note_id).await;
}

fn partly_layered_router() -> Router {
    Router::new()
        .route("/docs/:doc_id", delete(remove_covered_doc))
        .route_layer(middleware::from_fn(require_doc_owner))
        .route("/notes/:note_id", delete(remove_uncovered_note))
}
