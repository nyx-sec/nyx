use actix_web::web::{Data, Json};

pub async fn edit_message_same_id(
  Json(data): Json<EditMessage>,
  context: Data<LemmyContext>,
  local_user_view: LocalUserView,
) -> LemmyResult<Json<MessageResponse>> {
  check_local_user_valid(&local_user_view)?;
  let orig = Message::read(&mut context.pool(), data.message_id).await?;
  if local_user_view.person.id != orig.creator_id {
    return Err(LemmyErrorType::NoMessageEditAllowed.into());
  }
  Message::update(&mut context.pool(), data.message_id, &data.content).await?;
  Message::delete(&mut context.pool(), orig.id).await?;
  Ok(Json(MessageResponse::default()))
}
