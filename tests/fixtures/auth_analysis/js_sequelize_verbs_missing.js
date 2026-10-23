// Sequelize `destroy` and `upsert` are writes keyed by the request id.
// Pinned in `auth_analysis_tests`.
const express = require('express');
const router = express.Router();

router.delete('/d/:docId', async (req, res) => {
  await Doc.destroy({ where: { id: req.params.docId } });
  res.sendStatus(204);
});

router.put('/f/:docId', async (req, res) => {
  await Doc.upsert({ id: req.params.docId, title: req.body.title });
  res.sendStatus(204);
});

module.exports = router;
