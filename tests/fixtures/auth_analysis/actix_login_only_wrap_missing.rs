use actix_web::web;

fn require_login() {}

async fn remove_login_wrapped_doc(p: web::Path<String>, db: web::Data<Db>) {
    let doc_id = p.into_inner();
    db.delete_doc(&doc_id).await;
}

fn login_wrapped_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/docs")
            .wrap(require_login)
            .route("/{doc_id}", web::delete().to(remove_login_wrapped_doc)),
    );
}
