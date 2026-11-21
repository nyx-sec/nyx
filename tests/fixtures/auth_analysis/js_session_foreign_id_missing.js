// Recall guard for `js_session_userid_clean.js`: a request-supplied id still
// fires.  Pinned in `auth_analysis_tests`.
const express = require('express');
const router = express.Router();

router.get('/users/:id', async (req, res) => {
  const user = await db.user.findFirst({ where: { id: req.params.id } });
  res.json(user);
});

module.exports = router;
