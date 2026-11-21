const express = require('express');
const router = express.Router();

// `where: { id }` is `where: { id: id }`; the id comes from the request.
router.delete('/notes/:id', async (req, res) => {
  const { id } = req.params;
  await prisma.note.delete({ where: { id } });
  res.sendStatus(204);
});

module.exports = router;
