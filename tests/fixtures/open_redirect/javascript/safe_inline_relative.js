// Safe: inline relative-URL checks that reject protocol-relative values.

// Conjunction guarding the redirect.
function loginA(req, res) {
  const next = req.query.next;
  if (next.startsWith('/') && !next.startsWith('//')) {
    res.redirect(next);
  }
}

// Early return on either failure.
function loginB(req, res) {
  const next = req.query.next;
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) {
    return res.redirect('/');
  }
  res.redirect(next);
}

// Same checks in the other order.
function loginC(req, res) {
  const next = req.query.next;
  if (next.startsWith('//') || !next.startsWith('/')) {
    return res.redirect('/');
  }
  res.redirect(next);
}

module.exports = { loginA, loginB, loginC };
