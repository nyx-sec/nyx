use actix_web::web::{Data, Json};

// Same handler without the admin gate: both operations act on a client chosen
// community id with no authorization.
pub async fn purge_community_unguarded(
    Json(data): Json<PurgeCommunity>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<SuccessResponse>> {
    let community = Community::read(&mut context.pool(), data.community_id).await?;
    Community::delete(&mut context.pool(), data.community_id).await?;
    Ok(Json(SuccessResponse::default()))
}

// A gate that only runs on one branch does not dominate the delete.
pub async fn purge_community_conditional(
    Json(data): Json<PurgeCommunity>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<SuccessResponse>> {
    if data.reason.is_some() {
        is_admin(&local_user_view)?;
    }
    Community::delete(&mut context.pool(), data.community_id).await?;
    Ok(Json(SuccessResponse::default()))
}

// A discarded boolean result gates nothing.
pub async fn purge_community_ignored(
    Json(data): Json<PurgeCommunity>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<SuccessResponse>> {
    let _ = is_admin(&local_user_view).is_ok();
    Community::delete(&mut context.pool(), data.community_id).await?;
    Ok(Json(SuccessResponse::default()))
}

// The gate runs after the delete, so the delete is still unguarded.
pub async fn purge_community_late_gate(
    Json(data): Json<PurgeCommunity>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<SuccessResponse>> {
    Community::delete(&mut context.pool(), data.community_id).await?;
    is_admin(&local_user_view)?;
    Ok(Json(SuccessResponse::default()))
}
