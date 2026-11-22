const express = require('express');
const app = express();

// The session identity key is the signed-in caller, however the key is cased
// and whether it is read directly or through a local.
app.get('/orders', async (req, res) => {
  const uid = req.session.userId;
  const orders = await Order.find({ userId: uid });
  res.json(orders);
});

app.get('/me', async (req, res) => {
  const me = await User.findById(req.session.user_id);
  res.json(me);
});
