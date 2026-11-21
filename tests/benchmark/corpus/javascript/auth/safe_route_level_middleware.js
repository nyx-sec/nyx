const express = require('express');
const router = express.Router();

// Authorization middleware named on the route guards the whole handler.
router.get('/docs/:id', checkOwnership, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (!doc) return res.sendStatus(404);
  res.sendStatus(200);
});

router.put('/docs/:id', hasPermission('docs:write'), async (req, res) => {
  await Doc.updateOne({ _id: req.params.id }, req.body);
  res.sendStatus(204);
});

module.exports = router;
