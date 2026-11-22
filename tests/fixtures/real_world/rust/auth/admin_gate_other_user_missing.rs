use actix_web::web::{Data, Json};

// The gate tests a different value than the acting user, so it does not
// restrict who may reach the delete.
pub async fn purge_community_other(
    Json(data): Json<PurgeCommunity>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<SuccessResponse>> {
    is_admin(&other_user)?;
    Community::delete(&mut context.pool(), data.community_id).await?;
    Ok(Json(SuccessResponse::default()))
}
