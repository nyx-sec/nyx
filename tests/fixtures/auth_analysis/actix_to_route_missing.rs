use actix_web::web;

async fn remove_unwrapped_doc(p: web::Path<String>, db: web::Data<Db>) {
    let doc_id = p.into_inner();
    db.delete_doc(&doc_id).await;
}

fn unwrapped_config(cfg: &mut web::ServiceConfig) {
    cfg.route("/docs/{doc_id}", web::delete().to(remove_unwrapped_doc));
}
