// Real-repo motivation (meilisearch `GuardedData<P, D>` typed
// extractor on actix-web routes registered via `#[routes::path(..)]`
// attribute macros).
//
// Meilisearch's authorization extractor is
// `GuardedData<ActionPolicy<{ actions::KEYS_GET }>,
// Data<AuthController>>`.  Possessing the value proves the request
// passed the per-action permission check the inner Policy term
// encodes.  Routes are registered by attribute macro, not by the
// `.route("/p", web::get().to(handler))` builder pattern, so the
// actix_web extractor's route walk doesn't attach the handler as
// `RouteHandler` and never injected typed-extractor guard checks.
//
// The typed-extractor fallback pass in `actix_web::extract` now walks
// every Function-kind unit and applies `guard_calls_for_handler` to
// its parameter list, so the `GuardedData` parameter is recognised as
// a route-level policy guard (`AuthCheckKind::Other`,
// `is_route_level: true`) and the per-handler ownership rule no
// longer fires on path-derived sinks.

#![allow(dead_code, unused_variables)]

use std::marker::PhantomData;

pub struct ActionPolicy<const A: u8>;
pub struct Data<T>(pub T);

pub struct GuardedData<P, D> {
    data: D,
    _marker: PhantomData<P>,
}

impl<P, D> GuardedData<P, D> {
    pub fn into_inner(self) -> D {
        self.data
    }
}

pub mod web {
    pub struct Path<T>(pub T);
    impl<T> Path<T> {
        pub fn into_inner(self) -> T {
            unimplemented!()
        }
    }
}

pub struct AuthController;

impl AuthController {
    pub fn get_key(&self, uid: u64) -> Result<String, ()> {
        Ok(String::new())
    }
}

pub mod actions {
    pub const KEYS_GET: u8 = 1;
}

pub struct AuthParam {
    pub key: u64,
}

pub async fn get_api_key(
    auth_controller: GuardedData<ActionPolicy<{ actions::KEYS_GET }>, Data<AuthController>>,
    path: web::Path<AuthParam>,
) -> Result<String, ()> {
    let uid = path.into_inner().key;
    auth_controller.into_inner().0.get_key(uid)
}
