// Phase 09 (Track J.7) — JavaScript OPEN_REDIRECT vuln fixture.
//
// The Express handler splices `value` straight into `res.redirect`
// without host validation; an attacker URL routes the captured
// `Location:` header off-origin.
const express = require('express');

function run(req, res, value) {
  res.redirect(value);
}

module.exports = { run };
