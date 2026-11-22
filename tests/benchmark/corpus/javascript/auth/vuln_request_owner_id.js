// An `ownerId` taken from the query or the body is chosen by the caller.
// Pinning a lookup to it scopes nothing, and writing it reassigns the row.
const express = require('express');
const router = express.Router();

router.get('/read', async (req, res) => {
  const doc = await docStore.findDoc({ id: req.params.docId, ownerId: req.query.ownerId });
  res.sendStatus(200);
});

router.post('/reassign', async (req, res) => {
  await docStore.updateDoc({ id: req.params.docId }, { ownerId: req.body.ownerId });
  res.json({ ok: true });
});

module.exports = router;
