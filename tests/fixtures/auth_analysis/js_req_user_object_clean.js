const express = require('express');
const router = express.Router();

router.get('/docs/:docId', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId, owner: req.user });
  res.json(doc);
});

router.get('/docs3/:docId', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId, ownerId: req.user._id });
  res.json(doc);
});

module.exports = router;
