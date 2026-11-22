const express = require("express");
const { Doc } = require("./models");

const router = express.Router();

router.post("/docs", async (req, res) => {
  const d = await Doc.create({ ownerId: req.user.id, name: req.body.name });
  await Doc.destroy({ where: { id: d.id } });
  res.end();
});

module.exports = { router };
