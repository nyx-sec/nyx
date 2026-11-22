use actix_web::web::{Data, Json};

pub async fn edit_message_other_id(
  Json(data): Json<EditMessage>,
  context: Data<LemmyContext>,
  local_user_view: LocalUserView,
) -> LemmyResult<Json<MessageResponse>> {
  check_local_user_valid(&local_user_view)?;
  let orig = Message::read(&mut context.pool(), data.message_id).await?;
  if local_user_view.person.id != orig.creator_id {
    return Err(LemmyErrorType::NoMessageEditAllowed.into());
  }
  let other = Message::read(&mut context.pool(), data.other_id).await?;
  Message::update(&mut context.pool(), data.other_id, &data.content).await?;
  Message::delete(&mut context.pool(), other.id).await?;
  Ok(Json(MessageResponse::default()))
}
