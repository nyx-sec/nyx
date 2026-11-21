// Authorization middleware named on the route, or mounted on the router
// before it, guards the whole handler.  Pinned in `auth_analysis_tests`.
const express = require('express');
const router = express.Router();
const admin = express.Router();

admin.use(authorize('admin'));

router.get('/docs/:id', checkOwnership, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  res.json(doc);
});

router.put('/docs/:id', hasPermission('docs:write'), async (req, res) => {
  await Doc.updateOne({ _id: req.params.id }, req.body);
  res.sendStatus(204);
});

admin.delete('/docs/:docId', async (req, res) => {
  await Doc.deleteOne({ _id: req.params.docId });
  res.sendStatus(204);
});

module.exports = { router, admin };
