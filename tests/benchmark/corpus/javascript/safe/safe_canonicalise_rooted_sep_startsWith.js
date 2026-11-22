// js-safe-canonicalise-rooted-sep: path.resolve + .startsWith against a root
// that ends with a separator.  A sibling such as "/srv/uploads-old/x" no
// longer matches, so the prefix test is a real containment check.
const fs = require("fs");
const path = require("path");

const UPLOAD_ROOT = path.resolve("/srv/uploads") + path.sep;

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
