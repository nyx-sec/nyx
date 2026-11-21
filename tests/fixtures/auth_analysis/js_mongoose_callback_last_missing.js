// Recall guard for `js_array_callback_find_clean.ts`: a driver callback is
// the LAST argument, so this is still a data-layer read keyed by a request
// id.  Pinned in `auth_analysis_tests`.
const express = require('express');
const router = express.Router();

router.get('/notes/:id', (req, res) => {
  Note.findById(req.params.id, function (err, note) {
    res.json(note);
  });
});

module.exports = router;
