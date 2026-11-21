// The authenticated user, or one of its ids, pins the lookup to the caller.
const express = require('express');
const router = express.Router();

router.get('/docs/:docId', async (req, res) => {
  const doc = await docStore.findDoc({ id: req.params.docId, owner: req.user });
  res.sendStatus(200);
});

router.get('/mine/:docId', async (req, res) => {
  const doc = await docStore.findDoc({ id: req.params.docId, ownerId: req.user.id });
  res.sendStatus(200);
});

module.exports = router;
