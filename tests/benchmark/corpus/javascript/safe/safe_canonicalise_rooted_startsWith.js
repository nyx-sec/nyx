// js-safe-canonicalise-rooted: path.resolve + .startsWith with a
// non-literal root variable (an opaque prefix-lock).  Combined with
// path.resolve's dotdot=No proof, is_path_traversal_safe should suppress
// the FILE_IO sink even though the canonicalised path is absolute.
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
