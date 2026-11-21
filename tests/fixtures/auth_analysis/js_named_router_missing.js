// Routers are not always called `router` or `app`; a router bound from
// `express.Router()` registers routes whatever it is named.  Pinned in
// `auth_analysis_tests`.
const express = require('express');
const userRouter = express.Router();

userRouter.delete('/users/:userId', async (req, res) => {
  await User.deleteOne({ _id: req.params.userId });
  res.sendStatus(204);
});

module.exports = userRouter;
