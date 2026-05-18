// Phase 09 (Track J.7) — JavaScript OPEN_REDIRECT benign control
// fixture.
//
// The handler ignores the attacker-supplied value and redirects to a
// same-origin path; the captured `Location:` header carries no
// off-origin authority.
const express = require('express');

function run(req, res, value) {
  res.redirect('/dashboard');
}

module.exports = { run };
