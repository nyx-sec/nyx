const express = require('express');
const router = express.Router();

// The same SDK call on the server side of a route is where the check is due.
router.post('/feedback', async (req, res) => {
    await ghostApi.feedback.add({postId: req.body.postId});
    res.end();
});
