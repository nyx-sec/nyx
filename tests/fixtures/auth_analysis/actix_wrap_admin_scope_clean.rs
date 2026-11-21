use actix_web::web;

fn require_admin() {}

async fn dump_admin_stats() {
    stats_service::dump();
}

fn admin_scope_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .wrap(require_admin)
            .route("/stats", web::get().to(dump_admin_stats)),
    );
}
