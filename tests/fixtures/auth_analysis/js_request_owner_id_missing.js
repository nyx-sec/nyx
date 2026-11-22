const express = require('express');
const router = express.Router();

router.get('/read', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId, ownerId: req.query.ownerId });
  res.json(doc);
});

router.post('/reassign', async (req, res) => {
  await Doc.updateOne({ _id: req.params.docId }, { ownerId: req.body.ownerId });
  res.json({ ok: true });
});

module.exports = router;
