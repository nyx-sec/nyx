// js-path-traversal-sibling-prefix: path.resolve + .startsWith against a root
// that ends without a separator.  path.resolve drops a trailing separator, so
// "/srv/uploads-old/x" also passes the test and the sink is reached by a path
// outside the upload directory.
const fs = require("fs");
const path = require("path");

const UPLOAD_ROOT = path.resolve("/srv/uploads");

function serveFile(req, res) {
  const name = req.query.name;
  const target = path.resolve(path.join(UPLOAD_ROOT, name));
  if (!target.startsWith(UPLOAD_ROOT)) {
    res.status(403).end();
    return;
  }
  fs.readFile(target, (err, data) => res.send(data));
}

module.exports = { serveFile };
