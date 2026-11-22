use actix_web::web::{Data, Json};

pub async fn edit_private_message(
  Json(data): Json<EditPrivateMessage>,
  context: Data<LemmyContext>,
  local_user_view: LocalUserView,
) -> LemmyResult<Json<PrivateMessageResponse>> {
  check_local_user_valid(&local_user_view)?;
  let private_message_id = data.private_message_id;
  let orig = PrivateMessage::read(&mut context.pool(), private_message_id).await?;
  if local_user_view.person.id != orig.creator_id {
    return Err(LemmyErrorType::EditPrivateMessageNotAllowed.into());
  }
  PrivateMessage::update(&mut context.pool(), private_message_id, &data.content).await?;
  Ok(Json(PrivateMessageResponse::default()))
}
