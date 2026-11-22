const express = require('express');
const router = express.Router();

router.get('/admin/logs', requireAuth, async (req, res) => {
  res.json(await Log.find());
});

router.get('/admin/reports', requireAuth, checkRole(['viewer']), async (req, res) => {
  res.json(await Report.find());
});

router.get('/admin/exports', requireAuth, checkRole(['admin', 'viewer']), async (req, res) => {
  res.json(await Export.find());
});

module.exports = router;
