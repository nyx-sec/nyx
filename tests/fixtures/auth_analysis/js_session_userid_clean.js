// The caller's own id from the session (`req.session.userId`,
// `ctx.session.userId`) is self-scoped, for reads and for own-account writes.
// Pinned in `auth_analysis_tests`.
const express = require('express');
const router = express.Router();

router.get('/me', async (req, res) => {
  const me = await db.user.findFirst({ where: { id: req.session.userId } });
  res.json(me);
});

router.put('/me', async (req, res) => {
  await User.update({ name: req.body.name }, { where: { id: req.session.userId } });
  res.sendStatus(204);
});

module.exports = router;
