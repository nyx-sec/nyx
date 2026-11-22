const express = require("express");
const { Document } = require("./models");

const router = express.Router();

// The first lookup is keyed by a request id and nothing checks ownership, so
// it reports.  The parent id read off the loaded row afterwards does not.
router.get("/documents/:id", async (req, res) => {
  const doc = await Document.findByPk(req.params.id);
  const parent = await Document.findByPk(doc.parentDocumentId);
  res.json({ doc, parent });
});

// A helper that takes the raw id reports as well.
async function loadParent(parentDocumentId) {
  return Document.findByPk(parentDocumentId);
}

module.exports = { router, loadParent };
