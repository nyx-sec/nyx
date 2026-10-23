// Recall guard for `js_route_middleware_clean.js`: a route with no
// middleware, and a handler registered both with and without the check,
// stay unguarded.  Pinned in `auth_analysis_tests`.
const express = require('express');
const router = express.Router();

router.delete('/notes/:noteId', async (req, res) => {
  await Note.deleteOne({ _id: req.params.noteId });
  res.sendStatus(204);
});

async function removeDoc(req, res) {
  await Doc.deleteOne({ _id: req.params.docId });
  res.sendStatus(204);
}

router.delete('/guarded/docs/:docId', checkOwnership, removeDoc);
router.delete('/open/docs/:docId', removeDoc);

module.exports = router;
