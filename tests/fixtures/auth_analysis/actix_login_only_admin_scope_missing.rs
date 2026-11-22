use actix_web::web;

fn require_login() {}

async fn dump_login_only_stats() {
    stats_service::dump();
}

fn login_only_admin_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .wrap(require_login)
            .route("/stats", web::get().to(dump_login_only_stats)),
    );
}
