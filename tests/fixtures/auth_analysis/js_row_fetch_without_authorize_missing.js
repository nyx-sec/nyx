// Recall guard for `js_row_fetch_variants_clean.js`: the same fetches with no
// authorization on the row still fire.  Pinned in `auth_analysis_tests`.
async function readDocument(id) {
  const document = await Document.findByPk(id);
  document.viewed = true;
  return document;
}

async function readBoth(id, groupId) {
  const [document, group] = await Promise.all([
    Document.findByPk(id),
    Group.findByPk(groupId),
  ]);
  return [document, group];
}
