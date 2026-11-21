use actix_web::web;

fn require_doc_owner() {}

async fn remove_wrapped_doc(p: web::Path<String>, db: web::Data<Db>) {
    let doc_id = p.into_inner();
    db.delete_doc(&doc_id).await;
}

async fn remove_wrapped_note(p: web::Path<String>, db: web::Data<Db>) {
    let note_id = p.into_inner();
    db.delete_note(&note_id).await;
}

fn wrapped_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/docs")
            .wrap(require_doc_owner)
            .route("/{doc_id}", web::delete().to(remove_wrapped_doc)),
    );
    // `wrap` after the route covers it all the same.
    cfg.service(
        web::scope("/notes")
            .route("/{note_id}", web::delete().to(remove_wrapped_note))
            .wrap(require_doc_owner),
    );
}
