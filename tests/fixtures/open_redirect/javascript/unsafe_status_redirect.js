// Unsafe: the numeric status argument is not the redirect target.
function go(req, res) {
  res.redirect(303, req.query.next);
}

module.exports = go;
