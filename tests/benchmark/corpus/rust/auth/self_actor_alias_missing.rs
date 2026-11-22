use actix_web::web::{Data, Json};

// A mutation that merely receives the viewer is not scoped to it.
pub async fn delete_comment(
    Json(data): Json<DeleteComment>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<CommentResponse>> {
    check_local_user_valid(&local_user_view)?;
    Comment::delete(&mut context.pool(), data.comment_id, Some(&local_user_view.local_user)).await?;
    Ok(Json(CommentResponse::default()))
}

// A read with no viewer argument has nothing that scopes it.
pub async fn get_comment_anon(
    Json(data): Json<GetComment>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<CommentResponse>> {
    check_local_user_valid(&local_user_view)?;
    let comment_view = CommentView::read(&mut context.pool(), data.comment_id).await?;
    Ok(Json(CommentResponse { comment_view }))
}
