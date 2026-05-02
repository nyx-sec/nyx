// Negative counterpart for `safe_actix_guarded_data_extractor.rs`.
//
// Same handler shape (path-derived `uid` flows into
// `auth_controller.get_key(uid)`) but **without** the `GuardedData<P, D>`
// wrapper around the controller.  The handler now takes a bare
// `Data<AuthController>` and a typed `web::Path<AuthParam>` — no
// route-level capability check is implied by the parameter types.
// Pinned by `unsafe_actix_no_guarded_data_extractor` to guard against
// over-broad `policy_guard_names` recognition that would treat any
// handler with an actix-web parameter shape as authorised: the rule
// must still fire here.

#![allow(dead_code, unused_variables)]

pub struct Data<T>(pub T);

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

pub struct AuthParam {
    pub key: u64,
}

pub async fn get_api_key(
    auth_controller: Data<AuthController>,
    path: web::Path<AuthParam>,
) -> Result<String, ()> {
    let uid = path.into_inner().key;
    auth_controller.0.get_key(uid)
}
