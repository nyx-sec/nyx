// The tainted `flag` only picks the branch; the query in the body is a
// constant.  The `if` header must not take the body's `db.query` sink.
function handler(req, res, db) {
  const flag = req.query.flag;
  if (flag === "yes") {
    db.query("SELECT 1");
  }
  res.send("ok");
}

module.exports = handler;
