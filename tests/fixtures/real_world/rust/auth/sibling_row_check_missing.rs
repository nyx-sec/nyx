use actix_web::web::{Data, Json};

pub async fn delete_tag_sibling_check(
  Json(data): Json<DeleteTag>,
  context: Data<LemmyContext>,
  local_user_view: LocalUserView,
) -> LemmyResult<Json<Tag>> {
  let tag = Tag::read(&mut context.pool(), data.tag_id).await?;
  let sib = Tag::read(&mut context.pool(), tag.sibling_id).await?;
  check_community_mod_action(&local_user_view, &sib, false, &mut context.pool()).await?;
  let tag = Tag::delete(&mut context.pool(), data.tag_id).await?;
  Ok(Json(tag))
}
