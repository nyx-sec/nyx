// Unsafe: `startsWith('/')` alone accepts `//evil.example` and
// `/\evil.example`, both protocol-relative in a browser.
function login(req, res) {
  const next = req.query.next;
  if (!next.startsWith('/')) {
    return res.redirect('/');
  }
  res.redirect(next);
}

module.exports = login;
