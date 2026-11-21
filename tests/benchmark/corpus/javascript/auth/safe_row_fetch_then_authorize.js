// Fetch the row, authorize on it, keep working with it: the check covers the
// fetch whether the row is reassigned, written, or fetched in a Promise.all.
async function updateDocument(id, user, title) {
  let document = await Document.findByPk(id);
  authorize(user, 'update', document);
  document.title = title.trim();
  document = await documentUpdater(document, title);
  return document;
}

async function loadBoth(id, groupId, user) {
  const [document, group] = await Promise.all([
    Document.findByPk(id),
    Group.findByPk(groupId),
  ]);
  authorize(user, 'read', document);
  authorize(user, 'read', group);
  return [document, group];
}
