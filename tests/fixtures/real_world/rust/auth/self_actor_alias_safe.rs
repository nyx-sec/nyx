use actix_web::web::{Data, Json};

// `local_user_view.person.id` is the caller's own person id; passing it to the
// read scopes the view to the viewer.
pub async fn view_person(
    Json(data): Json<GetPerson>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<PersonResponse>> {
    check_local_user_valid(&local_user_view)?;
    let my_person_id = local_user_view.person.id;
    let person_view =
        PersonView::read(&mut context.pool(), data.person_id, Some(my_person_id), true).await?;
    Ok(Json(PersonResponse { person_view }))
}

// A read model that takes the signed-in viewer filters what the row exposes.
pub async fn view_comment(
    Json(data): Json<GetComment>,
    context: Data<LemmyContext>,
    local_user_view: LocalUserView,
) -> LemmyResult<Json<CommentResponse>> {
    check_local_user_valid(&local_user_view)?;
    let comment_view = CommentView::read(
        &mut context.pool(),
        data.comment_id,
        Some(&local_user_view.local_user),
        local_user_view.person.instance_id,
    )
    .await?;
    Ok(Json(CommentResponse { comment_view }))
}
