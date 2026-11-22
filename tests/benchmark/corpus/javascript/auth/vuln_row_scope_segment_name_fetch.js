const express = require("express");
const { Doc, db } = require("./models");

const router = express.Router();

router.post("/a", async (req, res) => {
  const d = await Doc.createdBy(req.body.name).first();
  await Doc.destroy({ where: { id: d.id } });
  res.end();
});

router.post("/b", async (req, res) => {
  const d = await db.createSession().findOne({ name: req.body.name });
  await Doc.destroy({ where: { id: d.id } });
  res.end();
});

router.post("/c", async (req, res) => {
  const d = await db.insertedDocs.findOne({ name: req.body.name });
  await Doc.destroy({ where: { id: d.id } });
  res.end();
});

module.exports = { router };
