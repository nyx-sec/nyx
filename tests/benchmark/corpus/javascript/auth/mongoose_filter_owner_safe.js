const express = require('express');
const router = express.Router();

router.put('/notes/:id', requireLogin, async (req, res) => {
  await Note.findOneAndUpdate(
    { _id: req.params.id, owner: req.user.id },
    { title: req.body.title },
  );
  res.json({ ok: true });
});

router.put('/notes/:id/body', requireLogin, async (req, res) => {
  await Note.updateOne({ _id: req.params.id, owner: req.user.id }, { $set: { body: req.body.body } });
  res.json({ ok: true });
});

module.exports = router;
