// Fetch the row, authorize on it, then keep working with it.  The check sits
// after the fetch, so it covers the fetch however the row binding is spelled:
// a later reassignment, a field write, sibling blocks, a Promise.all
// destructure, a ternary.  Pinned in `auth_analysis_tests`.
async function updateDocument(id, user, title) {
  let document = await Document.findByPk(id);
  authorize(user, 'update', document);
  document = await documentUpdater(document, title);
  return document;
}

async function renameDocument(id, user, title) {
  const document = await Document.findByPk(id);
  authorize(user, 'update', document);
  document.title = title.trim();
  return document.save();
}

async function loadEither(id, user, archived) {
  if (archived) {
    const document = await Archive.findByPk(id);
    authorize(user, 'read', document);
    return document;
  } else {
    const document = await Document.findByPk(id);
    authorize(user, 'read', document);
    return document;
  }
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

async function loadOrSelf(id, user) {
  const target = id ? await User.findByPk(id) : user;
  authorize(user, 'read', target);
  return target;
}
