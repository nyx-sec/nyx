use actix_web::web::{Data, Json};

pub async fn delete_community_tag(
  Json(data): Json<DeleteCommunityTag>,
  context: Data<LemmyContext>,
  local_user_view: LocalUserView,
) -> LemmyResult<Json<CommunityTag>> {
  let tag = CommunityTag::read(&mut context.pool(), data.tag_id).await?;
  let community = Community::read(&mut context.pool(), tag.community_id).await?;
  check_community_mod_action(&local_user_view, &community, false, &mut context.pool()).await?;
  let tag = CommunityTag::update(&mut context.pool(), data.tag_id, &data.form).await?;
  Ok(Json(tag))
}
