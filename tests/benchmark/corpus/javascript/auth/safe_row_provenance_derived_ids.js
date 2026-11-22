const { Collection, Document, Entry } = require("./models");

// The entity is handed in by the caller, which already loaded it.
async function moveDocument({ document, user }) {
  return Collection.findByPk(document.collectionId);
}

// The id on an inserted row was minted by the database.
async function createAndReload(db, uid, params) {
  const res = await db.createQueryBuilder(uid).insert(params.data).execute();
  const id = isRecord(res[0]) ? res[0].id : res[0];
  return Document.findOne({ where: { id } });
}

// Ids read off rows the unit just loaded.
async function removeMatching(db, uid, params) {
  const rows = await db.query(uid).findMany(params.where);
  return Promise.all(rows.map((row) => Entry.destroy(row.id)));
}

module.exports = { moveDocument, createAndReload, removeMatching };
