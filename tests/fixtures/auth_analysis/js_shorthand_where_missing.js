// ES6 shorthand properties carry the id: `where: { id }` is `where: { id: id
// }`.  Both Prisma and Sequelize take this form.  Pinned in
// `auth_analysis_tests`.
const express = require('express');
const router = express.Router();

router.get('/notes/:id', async (req, res) => {
  const { id } = req.params;
  const note = await prisma.note.findFirst({ where: { id } });
  res.json(note);
});

router.delete('/notes/:id', async (req, res) => {
  const { id } = req.params;
  await prisma.note.delete({ where: { id } });
  res.sendStatus(204);
});

module.exports = router;
