// Unsafe: a bare "/" prefix becomes "//evil.example" when the suffix
// starts with "/".
function go(req, res) {
  res.redirect('/' + req.query.next);
}

module.exports = go;
