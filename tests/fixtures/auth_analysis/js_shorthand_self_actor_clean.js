// Counterpart of `js_shorthand_where_missing.js`: the shorthand id is the
// caller's own, copied out of the authenticated user.  Pinned in
// `auth_analysis_tests`.
const express = require('express');
const router = express.Router();

router.get('/me/notes', async (req, res) => {
  const userId = req.user.id;
  const notes = await prisma.note.findMany({ where: { userId } });
  res.json(notes);
});

module.exports = router;
