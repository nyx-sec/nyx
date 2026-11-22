const express = require('express');
const app = express();

// A caught exception object has no attacker model as a property key or a
// redirect target, so none of these flows is reportable.
function probe(KEY, O) {
  try {
    '/./'[KEY](O);
  } catch (e) {
    try {
      O[e] = false;
      return true;
    } catch (f) {}
  }
  return false;
}

function copy(target) {
  try {
    risky();
  } catch (err) {
    target[err] = 1;
  }
}

app.get('/go', function (req, res) {
  try {
    risky();
  } catch (err) {
    res.redirect(err);
  }
});

module.exports = { probe, copy };
