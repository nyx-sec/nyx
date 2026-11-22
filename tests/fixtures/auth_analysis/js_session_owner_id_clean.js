const express = require('express');
const router = express.Router();

router.get('/mine/:docId', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId, ownerId: req.user.id });
  res.json(doc);
});

module.exports = router;
