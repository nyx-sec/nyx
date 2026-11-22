const express = require('express');
const router = express.Router();

router.put('/notes/:id/owner', requireLogin, async (req, res) => {
  await Note.findOneAndUpdate({ _id: req.params.id }, { owner: req.user.id });
  res.json({ ok: true });
});

router.put('/notes/:id/claim', requireLogin, async (req, res) => {
  await Note.updateOne({ _id: req.params.id }, { $set: { owner: req.user.id } });
  res.json({ ok: true });
});

module.exports = router;
