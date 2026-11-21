const express = require('express');
const passport = require('passport');
const router = express.Router();

router.get('/admin/users', passport.authenticate('jwt'), authorize('admin'), async (req, res) => {
  res.json(await User.find());
});

router.get('/admin/stats', requireAuth, checkRole(['admin']), async (req, res) => {
  res.json(await Stats.find());
});

router.get('/admin/audit', requireAuth, restrictTo('admin', 'superadmin'), async (req, res) => {
  res.json(await Audit.find());
});

module.exports = router;
