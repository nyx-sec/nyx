use actix_web::web::{Data, Json};

pub async fn edit_private_message_bad(
  Json(data): Json<EditPrivateMessage>,
  context: Data<LemmyContext>,
  local_user_view: LocalUserView,
) -> LemmyResult<Json<PrivateMessageResponse>> {
  check_local_user_valid(&local_user_view)?;
  let private_message_id = data.private_message_id;
  let orig = PrivateMessage::read(&mut context.pool(), private_message_id).await?;
  PrivateMessage::update(&mut context.pool(), private_message_id, &data.content).await?;
  Ok(Json(PrivateMessageResponse::default()))
}
