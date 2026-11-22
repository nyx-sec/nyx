use actix_web::web::{Data, Json};

// A body-level `is_admin(..)?;` returns early for everyone but admins, so the
// operations after it act on behalf of an admin, who may touch any community.
pub async fn purge_community(
    Json(data): Json<PurgeCommunity>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<SuccessResponse>> {
    is_admin(&local_user_view)?;
    let community = Community::read(&mut context.pool(), data.community_id).await?;
    Community::delete(&mut context.pool(), data.community_id).await?;
    Ok(Json(SuccessResponse::default()))
}
