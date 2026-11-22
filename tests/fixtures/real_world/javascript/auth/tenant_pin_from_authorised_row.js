const Router = require("koa-router");
const router = new Router();

router.post("revisions.export", auth(), async (ctx) => {
  const { id } = ctx.input.body;
  const { user } = ctx.state.auth;

  const revision = await Revision.findByPk(id, { rejectOnEmpty: true });
  const document = await Document.findByPk(revision.documentId, {
    userId: user.id,
    rejectOnEmpty: true,
  });
  authorize(user, "listRevisions", document);

  const attachmentIds = parseAttachmentIds(toProsemirror(revision));
  const pinned = await Attachment.findAll({
    where: { teamId: document.teamId, id: attachmentIds },
  });
  const unpinned = await Attachment.findAll({
    where: { id: attachmentIds },
  });
  ctx.body = { pinned, unpinned };
});

module.exports = router;
