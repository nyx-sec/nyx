const express = require('express');
const router = express.Router();

// The caller's own id from the session is self-scoped.
router.put('/me', async (req, res) => {
  await User.update({ name: req.body.name }, { where: { id: req.session.userId } });
  res.sendStatus(204);
});

module.exports = router;
